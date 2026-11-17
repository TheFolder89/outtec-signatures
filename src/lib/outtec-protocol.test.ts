import { strict as assert } from "node:assert";
import { test } from "node:test";
import { bridgeSignature, verifyBridgeRequest } from "./outtec-protocol.ts";

test("Outtec protocol binds the body, timestamp and nonce and rejects stale or malformed requests", () => {
  const body = '{"requestId":"test"}',
    timestamp = "1794873600",
    now = Number(timestamp) * 1000;
  const nonce = "12345678-1234-1234-1234-123456789012",
    secret = "a".repeat(64),
    signature = bridgeSignature(body, timestamp, nonce, secret);
  assert.equal(
    verifyBridgeRequest(body, timestamp, nonce, signature, secret, now),
    true,
  );
  assert.equal(
    verifyBridgeRequest(body + " ", timestamp, nonce, signature, secret, now),
    false,
  );
  assert.equal(
    verifyBridgeRequest(
      body,
      timestamp,
      nonce,
      signature,
      secret,
      now + 121000,
    ),
    false,
  );
  assert.equal(
    verifyBridgeRequest(body, timestamp, "invalid", signature, secret, now),
    false,
  );
  assert.equal(
    verifyBridgeRequest(body, timestamp, nonce, "x", secret, now),
    false,
  );
  assert.equal(
    verifyBridgeRequest(body, timestamp, nonce, signature, "short", now),
    false,
  );
});
