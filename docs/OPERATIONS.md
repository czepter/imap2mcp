# Operations

Step-by-step installation: `docs/INSTALL.md`. Upgrades and rollback: `docs/UPGRADING.md`. Symptoms: `docs/TROUBLESHOOTING.md`. Recovery: `docs/RECOVERY.md`.

## Deployment checklist

1. Run behind an HTTPS reverse proxy; set `BASE_URL` to the public https URL. The MCP resource (token audience) is `${BASE_URL}/mcp`; changing `BASE_URL` later invalidates every issued token (audience mismatch) and clients must re-authorize.
2. Create the master key outside the data directory and outside the image:
   ```bash
   openssl rand -hex 32 > secrets/imap2mcp_key && chmod 600 secrets/imap2mcp_key
   ```
   `docker-compose.yml` mounts it as a secret at `/run/secrets/imap2mcp_key` and sets `ENCRYPTION_KEY_FILE`. The file may contain 64 hex characters or a base64 32-byte key.
3. Set `SESSION_SECRET` (>= 32 characters) via your secret mechanism.
4. Make `data/` writable by uid 1000 (the container user) and persistent; the key file must be readable by uid 1000.
5. Start, read the bootstrap token from the log, finish `/setup` straight away.
6. Decide `REGISTRATION_MODE`: `dynamic` lets any client that can reach the server create an inert client record (it gets no access until you consent); `admin` removes that surface and you create clients in the UI.
7. If your mail server lives on a private address, list its exact host name in `ALLOW_PRIVATE_HOSTS`. IP literals are matched literally, so list `10.0.0.5` if you use that form.

## Environment variables

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `BASE_URL` | yes (production) | `http://localhost:3000` | Public URL. OAuth issuer; MCP resource/audience is `${BASE_URL}/mcp`. `https` enables `Secure` cookies, HSTS and trusts one proxy hop. |
| `ENCRYPTION_KEY_FILE` | one of the two | none | Path of a file holding the 32-byte master key (64 hex chars or base64). Preferred. |
| `ENCRYPTION_KEY` | one of the two | none | The same key inline (64 hex chars). Leaks into process listings; avoid. |
| `SESSION_SECRET` | yes (or `SESSION_SECRET_FILE`) | none | Cookie signing secret, at least 32 characters. |
| `SESSION_SECRET_FILE` | alternative | none | Path of a file holding the session secret (trimmed; same 32-character minimum). Used only when `SESSION_SECRET` is unset. Suited to Docker/Kubernetes secrets. |
| `DATA_DIR` | no | `./data` (`/app/data` in the image) | `bridge.db` (+WAL), `backups/`, `sidecar.sock`. |
| `PORT` | no | `3000` | Listen port inside the process/container. |
| `HOST_PORT` | no (compose) | `3000` | Port published on `127.0.0.1` by `docker-compose.yml`. |
| `REGISTRATION_MODE` | no | `dynamic` | `dynamic` (RFC 7591, grants nothing) or `admin` (clients created in the UI only). |
| `ALLOW_PRIVATE_HOSTS` | no | empty | Comma list of mailbox host names allowed to resolve to private/loopback addresses (exact match). |
| `ADMIN_BOOTSTRAP_TOKEN` | no | random, printed on first run | Fixed one-time `/setup` token. Unset it after setup. |
| `CORS_ORIGIN` | no | reflect | CORS origin for `/mcp` and the OAuth machine endpoints (never with credentials). |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error`. JSON lines on stdout; secrets redacted centrally. |
| `AUDIT_FAIL_MODE` | no | `closed` | `closed`: a tool call fails with `UNAVAILABLE` if its audit row cannot be written. `open`: log to stderr and continue (unaudited). |
| `AUDIT_RETENTION_DAYS` | no | `90` | Audit rows older than this are pruned at startup and every 24 h; `0` keeps them forever. |
| `SIDECAR_BIN` | no | `sidecar/bin/sidecar` | Sidecar binary path. |
| `SIDECAR_DISABLED` | no | off | `1`/`true`: v0 direct IMAP read path; debugging only. `/readyz` then reports `sidecar: disabled`. |
| `SIDECAR_EXTRA_CA_FILE` | no | none | Extra CA bundle for IMAP TLS in the sidecar. Pair with `NODE_EXTRA_CA_CERTS` for the Node path. |
| `SYNC_RECONCILE_SECS` | no | `30` | Interval of the sidecar's UID/flag reconciliation. |
| `IDLE_RENEW_SECS` | no | `1500` | IMAP IDLE is renewed this often (providers drop IDLE at about 29-30 min). |
| `IDLE_POLL_SECS` | no | `60` | Polling interval for servers without IDLE. |
| `SIDECAR_FOLDER_IDLE_SECS` | no | `3600` | How long the sidecar keeps a folder's IDLE watch open after its last use before releasing it. |
| `SIDECAR_AUTOSYNC_SECS` | no | sidecar default | Background sync interval; see `docs/DESIGN_V1.md`. |
| `RECONNECT_INITIAL_MS`, `RECONNECT_MAX_MS`, `RECONNECT_HEALTHY_MS` | no | `1000`, `60000`, `30000` | Reconnect backoff bounds (`min(60s, 1s*2^n)` with full jitter) and the healthy period that resets it. For tests only. |
| `NODE_EXTRA_CA_CERTS` | no | none | Node's own extra CA file (private CA for IMAP TLS on the Node path). |

The compose file forwards the variables it names (see `.env.example`); to set others, add them under `environment:` in a `docker-compose.override.yml`. The sidecar does not inherit the full environment, only the variables the bridge passes on explicitly.

## Health endpoints

| Endpoint | Meaning | Response |
|---|---|---|
| `GET /healthz` | Liveness: the process is serving. | `200 {"status":"ok"}` |
| `GET /readyz` | Readiness: DB readable; master key loads, round-trips a test vector and decrypts a stored mailbox secret if one exists (detects a wrong key); sidecar answers a ping (or is disabled); all migrations applied. | `200`/`503 {"status":"ok"\|"fail","checks":{"db","key","sidecar","migrations"}}` |

Unauthenticated, rate limited (120 requests per minute per client IP), `Cache-Control: no-store`, no host names, ids, paths or secrets. The Docker image `HEALTHCHECK` and the compose `healthcheck` use `/healthz` only. Use `/readyz` for your monitor or proxy upstream checks. Per-mailbox state (`ok`, `degraded`, `auth_failed`) is visible only in the authenticated admin UI.

## Shutdown

`SIGTERM`/`SIGINT` stop accepting connections, stop the audit pruner, stop the sidecar and the IMAP pool, close SQLite (WAL checkpoint) and exit 0, with a hard 15 s deadline. Compose sets `stop_grace_period: 20s`. An uncaught exception exits non-zero after the same sequence so the supervisor restarts the process; unhandled promise rejections are logged and do not stop it.

## Startup behavior (fail closed)

The process exits with `FATAL: ...` and a non-zero code for: no key configured, unreadable key file, key not 32 bytes hex/base64, all-zero key, the placeholder key from older example files, missing or short `SESSION_SECRET` (or unreadable `SESSION_SECRET_FILE`), invalid `REGISTRATION_MODE` or `BASE_URL`. A syntactically valid but **wrong** key does not stop startup (the admin UI must stay reachable so you can re-enter passwords); instead `/readyz` returns 503 with `"key":"fail"`, every operation on a mailbox whose secret cannot be decrypted fails, and no IMAP login is attempted with garbage. If tools suddenly fail after a redeploy, check `/readyz` and that the same key file is mounted. A database that cannot be opened, or a failed migration, stops startup with a `FATAL` log line and leaves the file untouched.

## Key handling

- Keep the key separate from database backups. A backup that contains both defeats the encryption.
- Back up the key through a different channel than the data (password manager, secret store). Without it, saved mailbox passwords are unrecoverable; you would re-enter them in the UI (OAuth clients, grants and tokens are unaffected because they do not depend on the key).
- Rotation is not implemented in v0. Each stored secret has the form `v1:<keyId>:<iv>:<ciphertext>:<tag>`; `keyId` is the first 8 hex characters of `sha256(key)` and is there to support rotation later. Current workaround: change the key, then re-enter each mailbox password in the UI.

## Backup and restore

SQLite in WAL mode: do not copy only `bridge.db` while running. Take a consistent online snapshot (works while serving) with the command in `docs/UPGRADING.md` ("Manual backup"), or stop the container and copy `bridge.db` with its `-wal`/`-shm` files. Upgrades take an automatic `VACUUM INTO` copy under `DATA_DIR/backups/` before migrating (newest 5 kept).

Restore by putting a backup file at `DATA_DIR/bridge.db` (remove stale `-wal`/`-shm`) with the matching key mounted and starting the server; verify `/readyz` and run **Test connection** on each mailbox. A restore with a different key starts but `/readyz` reports `key: fail` (RECOVERY.md). Restored databases bring back old token rows; revoke tokens in the UI if the backup is older than a revocation you care about. Full procedures: `docs/RECOVERY.md`, `docs/UPGRADING.md`.

Backups and the `backups/` directory contain the access audit (message identifiers are sensitive) and encrypted mailbox passwords: file mode 0600, keep them off shared storage.

## Revoking access

- Remove a single permission: **Clients -> client -> Grants**. Applies to the next tool call, including already issued tokens.
- Kill one token: **Dashboard -> Active tokens -> Revoke**.
- Cut off a client completely: **Dashboard -> Disable** (also revokes its tokens).
- Remove a mailbox: **Mailbox -> Delete**. Grants cascade; mail on the server is untouched.
- Rotating the IMAP password at the provider: edit the mailbox and enter the new password (leave empty to keep the old one). Changing host, port or username clears the Drafts folder selection.

Token lifetimes: access 1 hour, refresh 30 days, authorization code 10 minutes.

## Logs and audit

Stdout only: one JSON object per line (`ts`, `level`, `msg`, fields), level via `LOG_LEVEL`. Secrets (bearer tokens, passwords, authorization codes, the master key and `SESSION_SECRET` values) are redacted centrally; tests assert this. The first-run bootstrap token is printed as plain text on purpose, so treat the first-run log as sensitive until setup is complete. Every MCP request has a `requestId` (also the `X-Request-Id` response header, the tool error payload and the audit row).

Every tool attempt (allowed, denied, failed, cached) is recorded in the audit table; browse and download it under **Audit log** in the admin UI or with `docker compose exec imap-bridge node dist/audit/cli.js --format jsonl|csv [--from --to ...]`. Retention: `AUDIT_RETENTION_DAYS`.

## Upgrades

See `docs/UPGRADING.md`: automatic pre-migration backup, failed migrations abort startup without touching the database, roll-forward by default, restore-from-backup for rollback.

## Troubleshooting (short list; see `docs/TROUBLESHOOTING.md`)

| Symptom | Likely cause |
|---|---|
| Container exits immediately with `FATAL: ...` | Missing/invalid key or `SESSION_SECRET`; the message names the variable. |
| `/setup` returns 404 | An admin already exists. There is deliberately no reset route; the offline reset is in `docs/RECOVERY.md`. |
| Connection test: "Host resolves to a private..." | Add the exact host name to `ALLOW_PRIVATE_HOSTS`. |
| Connection test: "TLS certificate validation failed" | The server certificate is not trusted for that host name. Fix the certificate or, for a private CA, start the server with `NODE_EXTRA_CA_CERTS=/path/ca.pem`. Validation cannot be turned off. |
| Authentication failed | Wrong password, or the provider needs an app password / IMAP enabled. |
| All tools fail after a redeploy | Wrong or missing master key file (`/readyz` shows `key: fail`), or `BASE_URL` changed (tokens invalid -> 401 and clients re-authorize). |
| Client gets `FORBIDDEN` on everything | No grants for that client, or the token was consented without that capability. Edit grants; for a capability beyond the token's scopes the client must authorize again. |
| `UNKNOWN_OUTCOME` from `create_draft` / `move_message` | A write may or may not have reached the server. Check the Drafts or target folder before retrying; the server never retries writes itself. |
| `STALE_REFERENCE` | The folder's UIDVALIDITY changed. Search again to get fresh references. |
| 429 on login or token endpoint | In-memory rate limit; wait or restart the process. |
| Mailbox `auth_failed` | Credentials rejected; automatic attempts stopped. Fix at the provider, then **Retry** or edit the password (RECOVERY.md). |
