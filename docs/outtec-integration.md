# Outtec integration branch

Upstream base: `NYLLON-SOFTWARE/SignuDoc@1df503d85e4ae1da2ec8b7ed970119c5e6038516` (MIT). This branch adds an internal headless service; the existing upstream UI and authentication are not used as Outtec sender sessions.

## Deployment boundary

Run `db/migrate.mjs` against the dedicated engine database, then `npm run start:outtec` with Node 24. The process defaults to loopback; an isolated container may bind `0.0.0.0` on its private network. Never publish its port without the service authentication boundary. `/health` returns no secrets.

`POST /v1/outtec` uses a UUID nonce, timestamp (120-second window), SHA-256 of the exact JSON body and HMAC-SHA256. Nonces are single-use in PostgreSQL. Each mutation has a stable operation UUID and body fingerprint; PostgreSQL advisory locks serialize requests. Recoverable creation reuses its exclusive non-interactive owner and envelope. No arbitrary document URL is fetched.

Supported actions: create, fields, send, cancel, status, signing, submit, artifact, send-code and verify-code. Outtec authenticates current identities and domain permissions before calling the service. External guests require a code sent to their specified email. Raw codes and tokens are not included in integration logs or operation results.

The R2 storage driver accepts the configured Cloudflare HTTPS endpoint and private bucket only; all objects are under `signature-engine/`. Original PDFs are limited to 20 MiB and already signed PDFs are refused to avoid invalidating signatures. Outtec preserves original/final PDFs and certificate hashes in its own private namespace as well.

`OUTTEC_BRIDGE_MODE=true` selects the versioned Portuguese consent disclosure. `OUTTEC_BRIDGE_SECRET` and `BETTER_AUTH_SECRET` must be separate strong secrets. Keep the seal secret stable and back it up securely. Signatures are simple electronic signatures with the installation's PAdES seal and hash-chain evidence. **ICP-Brasil is not available or homologated.** An `ICP_BRASIL` request may be prepared but the service refuses to send or sign it with the simple method.

For isolated staging use `EMAIL_DRIVER=capture`, loopback `APP_URL` and a private capture directory. Captured mail proves adapter behavior only; it does not prove external delivery. Production email and qualified signing require their own configuration and acceptance. Do not expose captured messages or test fixtures.

The existing upstream license and third-party notices remain applicable. Upstream updates require review and regression tests; this branch does not change any Outtec production or main branch.
