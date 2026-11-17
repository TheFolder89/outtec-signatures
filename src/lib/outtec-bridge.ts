import { createHmac } from "node:crypto";
import { z } from "zod";
import { getDb, type DbExecutor } from "./db/connection.ts";
import { createDraftEnvelope, getPrepareEnvelopeDataForUser, replaceDraftEnvelopeSigners, replaceDraftEnvelopeFields, sendDraftEnvelope, voidSentEnvelope } from "./envelopes.ts";
import { getSigningPayloadForToken, recordSignerConsent, submitSigningForToken, sendSignerEmailCode, verifySignerCheck } from "./signing.ts";
import { createStorageService } from "./services/storage.ts";
import { hashOpaqueToken } from "./services/opaque-tokens.ts";
import { verifyAuditChain } from "./services/audit.ts";
import { bridgeDigest } from "./outtec-protocol.ts";

export const outtecCommandSchema = z.object({ requestId: z.uuid(), operationId: z.uuid(), action: z.enum(["create", "fields", "send", "cancel", "status", "signing", "submit", "artifact", "send-code", "verify-code"]), payload: z.record(z.string(), z.unknown()) });
type BridgeCommand = z.infer<typeof outtecCommandSchema>;
type Binding = { owner_id: string; envelope_id: string | null; source_hash: string; signature_method: string };
const sender = { senderEmail: "signatures@outtec.invalid", senderName: "outTEC" };

async function binding(requestId: string): Promise<Binding> {
  const result = await getDb().query<Binding>("SELECT owner_id, envelope_id, source_hash, signature_method FROM outtec_bridge_requests WHERE request_id=$1", [requestId]);
  if (!result.rows[0]?.envelope_id) throw Object.assign(new Error("Request not prepared."), { statusCode: 404 });
  return result.rows[0];
}

async function state(requestId: string) {
  const record = await binding(requestId), database = getDb();
  const envelope = (await database.query("SELECT id,status,expires_at,signed_pdf_key,evidence_key,source_pdf_hash,completed_at FROM envelopes WHERE id=$1 AND user_id=$2", [record.envelope_id, record.owner_id])).rows[0];
  if (!envelope || envelope.source_pdf_hash !== record.source_hash) throw new Error("Document binding failed.");
  const prepared = await getPrepareEnvelopeDataForUser(record.owner_id, record.envelope_id!, { database });
  const signers = (await database.query('SELECT id,name,email,status,signed_at AS "signedAt" FROM signers WHERE envelope_id=$1 ORDER BY sign_order', [record.envelope_id])).rows;
  const revision = Number((await database.query("SELECT coalesce(max(sequence),0) AS revision FROM audit_events WHERE envelope_id=$1", [envelope.id])).rows[0].revision);
  return { envelopeId: envelope.id, sourceHash: record.source_hash, revision, status: envelope.status === "sent" && envelope.expires_at && envelope.expires_at <= Date.now() / 1000 ? "expired" : envelope.status, pageCount: prepared!.pageCount, pages: prepared!.pages, fields: prepared!.fields.map(({ id, signerId, type, page, x, y, width, height, required, label }) => ({ id, signerId, type, page, x, y, width, height, required, label })), signers, auditChainValid: (await verifyAuditChain(envelope.id, database)).ok };
}

async function create(command: BridgeCommand) {
  const input = z.object({ title: z.string().trim().min(3).max(180), fileName: z.string().max(180), sourcePdf: z.string().max(29_000_000), sourceHash: z.string().regex(/^[a-f0-9]{64}$/), method: z.enum(["SIMPLE", "ICP_BRASIL"]), signers: z.array(z.object({ name: z.string().min(2).max(160), email: z.email(), purpose: z.string().min(2).max(120), userId: z.string().optional() })).min(1).max(10) }).parse(command.payload);
  const bytes = Buffer.from(input.sourcePdf, "base64");
  if (bytes.length > 20 * 1024 * 1024 || bridgeDigest(bytes.toString("base64")) !== bridgeDigest(input.sourcePdf) || (await import("node:crypto")).createHash("sha256").update(bytes).digest("hex") !== input.sourceHash) throw Object.assign(new Error("Invalid source PDF."), { statusCode: 400 });
  if (/\/ByteRange\s*\[/.test(bytes.toString("latin1"))) throw Object.assign(new Error("Existing signatures must be preserved."), { statusCode: 400 });
  const ownerId = `outtec-${command.requestId}`, database = getDb();
  const existing = (await database.query<Binding>("SELECT owner_id,envelope_id,source_hash,signature_method FROM outtec_bridge_requests WHERE request_id=$1", [command.requestId])).rows[0];
  if (existing && (existing.source_hash !== input.sourceHash || existing.signature_method !== input.method)) throw Object.assign(new Error("Request binding conflict."), { statusCode: 409 });
  await database.query('INSERT INTO public."user"(id,name,email,"emailVerified") VALUES($1,$2,$3,true) ON CONFLICT(id) DO NOTHING', [ownerId, "outTEC · solicitação isolada", `${command.requestId}@bridge.outtec.invalid`]);
  await database.query("INSERT INTO outtec_bridge_requests(request_id,owner_id,source_hash,signature_method) VALUES($1,$2,$3,$4) ON CONFLICT(request_id) DO NOTHING", [command.requestId, ownerId, input.sourceHash, input.method]);
  let envelopeId = existing?.envelope_id;
  if (!envelopeId) {
    // Recover the envelope if the process stopped after its creation and before
    // binding it. The request lock and its exclusive owner prevent duplication.
    const recovered = (await database.query("SELECT id FROM envelopes WHERE user_id=$1 AND source_pdf_hash=$2 ORDER BY created_at LIMIT 1", [ownerId, input.sourceHash])).rows[0];
    envelopeId = recovered?.id ?? (await createDraftEnvelope(ownerId, { title: input.title, sourcePdf: { body: bytes, filename: input.fileName, contentType: "application/pdf" } })).envelope.id;
    await database.query("UPDATE outtec_bridge_requests SET envelope_id=$2 WHERE request_id=$1 AND envelope_id IS NULL", [command.requestId, envelopeId]);
  }
  const current = await state(command.requestId);
  if (current.status === "draft" && !current.signers.length) await replaceDraftEnvelopeSigners(ownerId, envelopeId!, { signers: input.signers.map((p, i) => ({ name: p.name, email: p.email, signOrder: i + 1, requireEmailCode: !p.userId })) });
  return state(command.requestId);
}

async function signingToken(command: BridgeCommand): Promise<string> {
  const input = z.object({ actorEmail: z.email(), actorUserId: z.string().min(1).max(128) }).passthrough().parse(command.payload);
  const record = await binding(command.requestId);
  if (record.signature_method !== "SIMPLE") throw Object.assign(new Error("ICP-Brasil provider is not homologated."), { statusCode: 503 });
  const database = getDb();
  const signer = (await database.query("SELECT s.id,s.status,e.status AS envelope_status,e.expires_at FROM signers s JOIN envelopes e ON e.id=s.envelope_id WHERE s.envelope_id=$1 AND lower(s.email)=$2", [record.envelope_id, input.actorEmail.toLowerCase()])).rows[0];
  if (!signer || signer.status !== "notified" || signer.envelope_status !== "sent" || signer.expires_at <= Date.now() / 1000) throw Object.assign(new Error("This identity is not the active signer."), { statusCode: 409 });
  const token = createHmac("sha256", process.env.OUTTEC_BRIDGE_SECRET!).update(`outtec-session\n${command.requestId}\n${signer.id}\n${input.actorUserId}`).digest("base64url");
  await database.query("UPDATE signers SET signing_token_hash=$1,signing_token_expires_at=$2 WHERE id=$3 AND status='notified'", [hashOpaqueToken(token), signer.expires_at, signer.id]);
  return token;
}

async function execute(command: BridgeCommand) {
  if (command.action === "create") return create(command);
  const record = await binding(command.requestId);
  if (command.action === "status") return state(command.requestId);
  if (command.action === "artifact") {
    const kind = z.enum(["signed", "certificate"]).parse(command.payload.kind);
    const envelope = (await getDb().query("SELECT status,signed_pdf_key,evidence_key FROM envelopes WHERE id=$1", [record.envelope_id])).rows[0];
    if (envelope?.status !== "completed") throw Object.assign(new Error("Completed artifact unavailable."), { statusCode: 409 });
    const file = await createStorageService().getObject(kind === "signed" ? envelope.signed_pdf_key : envelope.evidence_key);
    const bytes = Buffer.from(file.body);
    return { base64: bytes.toString("base64"), sha256: (await import("node:crypto")).createHash("sha256").update(bytes).digest("hex") };
  }
  if (command.action === "fields") await replaceDraftEnvelopeFields(record.owner_id, record.envelope_id!, command.payload);
  else if (command.action === "send") {
    if (record.signature_method !== "SIMPLE") throw Object.assign(new Error("ICP-Brasil provider is not homologated."), { statusCode: 503 });
    if ((await state(command.requestId)).status === "draft") {
      const input = z.object({ expiresInDays: z.number().int().min(3).max(90), permittedUseConfirmed: z.literal(true) }).passthrough().parse(command.payload);
      await sendDraftEnvelope(record.owner_id, record.envelope_id!, { ...sender, expiresInDays: input.expiresInDays, signatureLevel: "simple", deliveryMode: "outtec" });
    }
  } else if (command.action === "cancel") {
    const reason = z.string().trim().min(5).max(500).parse(command.payload.reason);
    const current = await state(command.requestId);
    if (current.status === "draft") throw Object.assign(new Error("Only sent envelopes can be cancelled."), { statusCode: 409 });
    if (current.status !== "voided") await voidSentEnvelope(record.owner_id, record.envelope_id!, { ...sender, reason });
  } else if (command.action === "signing") {
    const token = await signingToken(command), payload = await getSigningPayloadForToken(token, { verifiedMethods: command.payload.guestVerified === true ? ["email_code"] : [] });
    return { currentSignerFields: payload.currentSignerFields, visibleFields: payload.visibleFields, disclosure: payload.disclosure, pageCount: payload.pageCount, pages: payload.pages, signerName: payload.currentSignerFields[0]?.signerName ?? "" };
  } else if (command.action === "send-code") {
    await sendSignerEmailCode(await signingToken(command));
    return { accepted: true };
  } else if (command.action === "verify-code") {
    await verifySignerCheck(await signingToken(command), { method: "email_code", code: z.string().regex(/^\d{6}$/).parse(command.payload.code) });
    return { confirmed: true };
  } else if (command.action === "submit") {
    const actorEmail = z.email().parse(command.payload.actorEmail);
    const current = await state(command.requestId);
    if (current.signers.find(p => p.email.toLowerCase() === actorEmail.toLowerCase())?.status !== "signed") {
      const token = await signingToken(command);
      const requestMeta = { userAgent: `outTEC authenticated identity ${z.string().max(128).parse(command.payload.actorUserId)}` };
      const verifiedMethods = command.payload.guestVerified === true ? ["email_code" as const] : [];
      await recordSignerConsent(token, { disclosureVersion: command.payload.disclosureVersion }, { requestMeta, verifiedMethods });
      await submitSigningForToken(token, { fields: command.payload.fields, clientTimezoneOffsetMinutes: 180 }, { requestMeta, verifiedMethods, deliveryMode: "outtec" });
    }
  }
  return state(command.requestId);
}

export async function executeOuttecCommand(input: unknown) {
  const command = outtecCommandSchema.parse(input), database = getDb();
  const lock = await database.connect();
  try {
    await lock.query("SELECT pg_advisory_lock(hashtextextended($1,82711))", [command.requestId]);
    if (["status", "signing", "artifact"].includes(command.action)) return await execute(command);
    const inputHash = bridgeDigest(JSON.stringify(command));
    const existing = (await lock.query("SELECT request_id,input_hash,result FROM outtec_bridge_operations WHERE id=$1", [command.operationId])).rows[0];
    if (existing && (existing.request_id !== command.requestId || existing.input_hash !== inputHash)) throw Object.assign(new Error("Operation identity conflict."), { statusCode: 409 });
    if (existing?.result) return existing.result;
    await lock.query("INSERT INTO outtec_bridge_operations(id,request_id,input_hash) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING", [command.operationId, command.requestId, inputHash]);
    const result = await execute(command);
    await lock.query("UPDATE outtec_bridge_operations SET result=$2 WHERE id=$1", [command.operationId, JSON.stringify(result)]);
    return result;
  } finally { await lock.query("SELECT pg_advisory_unlock(hashtextextended($1,82711))", [command.requestId]).catch(() => undefined); lock.release(); }
}

export async function consumeBridgeNonce(nonce: string, database: DbExecutor = getDb()) {
  const result = await database.query("INSERT INTO outtec_bridge_nonces(nonce) VALUES($1) ON CONFLICT DO NOTHING RETURNING nonce", [nonce]);
  if (result.rowCount !== 1) throw Object.assign(new Error("Replayed request."), { statusCode: 409 });
  await database.query("DELETE FROM outtec_bridge_nonces WHERE created_at < now() - interval '10 minutes'");
}
