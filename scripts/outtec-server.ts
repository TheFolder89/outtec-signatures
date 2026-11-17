import { createServer } from "node:http";
import {
  executeOuttecCommand,
  consumeBridgeNonce,
} from "../src/lib/outtec-bridge.ts";
import { verifyBridgeRequest } from "../src/lib/outtec-protocol.ts";
import { getDb } from "../src/lib/db/connection.ts";

const secret = process.env.OUTTEC_BRIDGE_SECRET ?? "";
if (secret.length < 32)
  throw new Error("OUTTEC_BRIDGE_SECRET must contain at least 32 characters.");
const port = Number(process.env.PORT ?? 3199);
const server = createServer(async (request, response) => {
  response.setHeader("Cache-Control", "private, no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  if (request.url === "/health" && request.method === "GET") {
    try {
      await getDb().query("SELECT 1 FROM outtec_bridge_requests LIMIT 1");
      response.end(
        JSON.stringify({
          ready: true,
          service: "outtec-signatures",
          revision: process.env.OUTTEC_RELEASE_SHA ?? "development",
          icpBrasil: false,
        }),
      );
    } catch {
      response.statusCode = 503;
      response.end('{"ready":false}');
    }
    return;
  }
  if (request.url !== "/v1/outtec" || request.method !== "POST") {
    response.statusCode = 404;
    response.end();
    return;
  }
  try {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > 30_000_000)
        throw Object.assign(new Error("Request too large."), {
          statusCode: 413,
        });
      chunks.push(Buffer.from(chunk));
    }
    const body = Buffer.concat(chunks).toString("utf8");
    const header = (name: string) =>
      typeof request.headers[name] === "string"
        ? (request.headers[name] as string)
        : "";
    const nonce = header("x-outtec-nonce");
    if (
      !verifyBridgeRequest(
        body,
        header("x-outtec-time"),
        nonce,
        header("x-outtec-signature"),
        secret,
      )
    ) {
      response.statusCode = 401;
      response.end('{"error":"Unauthorized"}');
      return;
    }
    await consumeBridgeNonce(nonce);
    const result = await executeOuttecCommand(JSON.parse(body));
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify(result));
  } catch (error) {
    const status = (error as { statusCode?: number }).statusCode;
    response.statusCode =
      typeof status === "number" && status >= 400 && status <= 599
        ? status
        : error instanceof Error &&
            (error.name === "ZodError" || error instanceof SyntaxError)
          ? 400
          : 500;
    // Never log documents, signing tokens, email addresses, provider responses or secrets.
    process.stderr.write(
      JSON.stringify({
        event: "OUTTEC_BRIDGE_FAILED",
        status: response.statusCode,
        errorType: error instanceof Error ? error.name : "Unknown",
      }) + "\n",
    );
    response.end(
      JSON.stringify({
        error: "Signature operation could not be confirmed.",
        status: response.statusCode,
      }),
    );
  }
});
server.requestTimeout = 125_000;
server.headersTimeout = 15_000;
server.listen(port, process.env.BIND_ADDRESS ?? "127.0.0.1", () =>
  process.stdout.write(
    JSON.stringify({ service: "outtec-signatures", port, icpBrasil: false }) +
      "\n",
  ),
);
