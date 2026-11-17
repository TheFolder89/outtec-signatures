import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export function bridgeDigest(body: string): string { return createHash("sha256").update(body).digest("hex"); }
export function bridgeSignature(body: string, timestamp: string, nonce: string, secret: string): string {
  return createHmac("sha256", secret).update(`${timestamp}\n${nonce}\n${bridgeDigest(body)}`).digest("hex");
}
export function verifyBridgeRequest(body: string, timestamp: string, nonce: string, signature: string, secret: string, now = Date.now()): boolean {
  if (secret.length < 32 || !/^\d{10}$/.test(timestamp) || Math.abs(now / 1000 - Number(timestamp)) > 120 || !/^[a-f0-9-]{36}$/.test(nonce) || !/^[a-f0-9]{64}$/.test(signature)) return false;
  return timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(bridgeSignature(body, timestamp, nonce, secret), "hex"));
}
