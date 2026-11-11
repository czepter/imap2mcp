# Troubleshooting

Start with the two health endpoints and the log:

```bash
curl -s http://127.0.0.1:3000/healthz            # liveness: {"status":"ok"} if the process serves
curl -s http://127.0.0.1:3000/readyz             # readiness: which check fails?
docker compose ps                                # healthy / unhealthy / restarting
docker compose logs --tail 100 imap-bridge       # JSON lines; secrets are redacted
```

`/readyz` returns `{"status":"ok"|"fail","checks":{"db","key","sidecar","migrations"}}` with HTTP 200 or 503. The check values are `ok`, `fail`, or (sidecar only) `disabled` when `SIDECAR_DISABLED` is set. They deliberately say nothing more; the log has details.

## By readiness check

| Failing check | Meaning | What to do |
|---|---|---|
| `db: fail` | The SQLite file cannot be read. | Disk full or permissions on `data/` (must be writable by uid 1000); corruption: RECOVERY.md "Corrupt database". |
| `key: fail` | The configured master key cannot decrypt what is in the database (a stored mailbox secret). The key is *valid* but not the one the data was written with, or the stored data is damaged. | Mount the original key file (compare `keyId`: the first 8 hex characters of `sha256` of the key appear in stored ciphertexts as `v1:<keyId>:...`). If the key is truly lost: RECOVERY.md "Lost master key". Tools for such mailboxes fail until fixed; no IMAP login is attempted with garbage. |
| `sidecar: fail` | The Go sidecar does not answer a ping within 2 s. It is supervised and restarted with backoff (observed: a killed sidecar was back within a second). | If it persists: look for `"component":"sidecar"` lines in the log; check that `sidecar/bin/sidecar` exists in the image and that `data/` is writable (the socket is `data/sidecar.sock`). Reads fail with `UPSTREAM_ERROR`/`UNAVAILABLE` meanwhile. Last resort for diagnosis only: `SIDECAR_DISABLED=1` (direct IMAP path, no cache). |
| `migrations: fail` | A migration shipped in this build is not applied. Normally impossible after a successful start. | See UPGRADING.md; check the log for migration errors. |

## Container does not start or keeps restarting

Read the first `FATAL` line in `docker compose logs imap-bridge`.

| Message | Cause and fix |
|---|---|
| `FATAL: No encryption key configured...` | Neither `ENCRYPTION_KEY_FILE` nor `ENCRYPTION_KEY` is set. With the compose file the secret `./secrets/imap2mcp_key` must exist before `docker compose up`. |
| `FATAL: Cannot read ENCRYPTION_KEY_FILE (...): EACCES` | The key file is not readable by uid 1000: `sudo chown 1000:1000 secrets/imap2mcp_key`. |
| `... must contain a 32-byte key encoded as 64 hex chars or base64` / `all-zero key` | The file content is wrong. Regenerate only for a fresh install; for existing data you need the original (RECOVERY.md). |
| `FATAL: Invalid configuration: - SESSION_SECRET is required` / `must be at least 32 characters` | Set `SESSION_SECRET` in `.env` (`openssl rand -hex 32`). |
| `Invalid configuration: - BASE_URL is not a valid URL` / `REGISTRATION_MODE must be...` | Fix `.env`. |
| `FATAL: database could not be opened or migrated` with `SQLITE_CANTOPEN` | `data/` is not writable by uid 1000 (`sudo chown 1000:1000 data`). |
| same, with `SQLITE_NOTADB` / `malformed` | The database file is damaged or not a database: RECOVERY.md "Corrupt database". |
| same, with `Database migration failed` | The original database is untouched and a `backups/bridge-...-pre-<n>.db` exists. Keep the log, see UPGRADING.md; report it. |

The container restarts automatically (`restart: unless-stopped`); `docker compose stop` ends the loop.

## Reverse proxy / TLS

| Symptom | Cause and fix |
|---|---|
| Login works but cookies are not kept, or redirects go to `http://` | The proxy does not send `X-Forwarded-Proto: https`, or `BASE_URL` is `http://`. Use the example configs. |
| Rate-limit `429` hits everyone at once | The proxy does not forward the client address (`X-Forwarded-For`), so all requests share the proxy's IP. |
| MCP calls hang or arrive in one piece late | Response buffering in the proxy. Disable it (`flush_interval -1` / `proxy_buffering off`). |
| `401` on every `/mcp` call after changing the domain | Tokens are bound to `BASE_URL`; clients must re-authorize. |
| The admin UI shows a blank page or its files under `/_nuxt/` return 404 | The UI is built for the root path of the host. Serve the bridge at `https://host/` (no path prefix) and proxy every path, including `/_nuxt/*`, `/api/*` and `/oauth/authorize`, to the app. A blank page with a Content-Security-Policy error in the browser console usually means the proxy rewrote or injected HTML (the CSP allows only the app's own scripts). |
| Admin actions fail with `403` and error code `csrf` ("session expired" style message) | The session cookie was not sent (cookie not kept, see the first row), the session ended (logout in another tab, `SESSION_SECRET` changed, 24 h expiry), or a proxy strips the `X-CSRF-Token` header. Reload the page; if it persists, fix the proxy. |
| Browser shows the page but `/readyz` is 429 | More than 120 health requests per minute from one address; lower the probe frequency. |

## Mailboxes and tools

| Symptom | Cause and fix |
|---|---|
| Mailbox shows **Authentication failed** | The server rejected the credentials, so automatic attempts stopped (by design, to avoid lockouts). Fix the password or enable IMAP/app passwords at the provider, then press **Retry** (or edit the credentials). Tools answer `AUTH_FAILED` immediately meanwhile. |
| Connection test: "Host resolves to a private..." | Add the exact host name to `ALLOW_PRIVATE_HOSTS` in `.env` and run `docker compose up -d` (`docker compose restart` does **not** re-read `.env`). |
| Connection test: TLS certificate error | Fix the server certificate or trust your CA via `NODE_EXTRA_CA_CERTS` and `SIDECAR_EXTRA_CA_FILE` (INSTALL.md section 7 has a ready-made `docker-compose.override.yml`; the file must be a valid PEM readable by uid 1000, otherwise the sidecar exits at start). Apply with `docker compose up -d`. Validation cannot be disabled. |
| Tools return `UNAVAILABLE` for everything and the log mentions audit | The audit row could not be written and `AUDIT_FAIL_MODE=closed` (default) refuses to serve unaudited. Check disk space and `/readyz`. Set `open` only if you accept unaudited access. |
| Tools return `UNAVAILABLE` with `operatorAction` "The server cannot decrypt stored mailbox credentials; check ENCRYPTION_KEY / key file" (not retryable); `/readyz` shows `key: fail` | The master key does not match the one the mailbox password was stored under (wrong or replaced key file). Restore the original key file and run `docker compose up -d`; if it is lost, RECOVERY.md "Lost master key". No IMAP login is attempted meanwhile. |
| `UPSTREAM_ERROR` ("Mailbox operation failed") on reads | The response is deliberately generic. The log has the reason: search for the `requestId` from the error and read the `read failed` line (`cause` holds the sidecar/IMAP error, one line per attempt, up to 3). Failing in about 1 s means an immediate error (not a timeout, which takes the full budget). | Fix according to `cause`. |
| `FORBIDDEN` for everything | The client has no grants. **Clients -> client**. |
| `UNKNOWN_OUTCOME` | A write may or may not have been applied; check the target folder before retrying. The server never replays writes. |
| `STALE_REFERENCE` | The folder's UIDVALIDITY changed; search again. |
| New mail appears late | The sidecar reconciles every `SYNC_RECONCILE_SECS` (30) and uses IDLE where the server supports it; polling every 60 s otherwise. |
| `/setup` is 404 | An admin exists. Offline reset: RECOVERY.md. |

## Misc

- Admin sessions are sealed cookies (no server-side session store, so there is no `MemoryStore` warning and a restart does not sign you out). You are signed out when the 24 h cookie expires, after you log out, or when `SESSION_SECRET` changes; OAuth tokens are unaffected. The first start of the Nuxt release after the Express release asks for one fresh login (UPGRADING.md).
- Increase log detail with `LOG_LEVEL=debug` in `.env`, then `docker compose up -d` (not `restart`: that keeps the old environment). Secrets stay redacted.
- Docker reports `unhealthy` only for failed liveness (`/healthz`). A wrong key does not make the container unhealthy on purpose; look at `/readyz`.
