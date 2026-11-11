# v2 Design Contract — Production hardening

> **Note (Nuxt migration):** this is the v2 design as it was written. Paths such as `src/...`, and mentions of Express, server-rendered pages, `src/web/**` or middleware, describe the code at that time. The domain code now lives in `server/core/`, the admin UI is a Nuxt single-page app over a JSON API (`/api`, header-token CSRF, sealed-cookie sessions) and the server is Nitro; see `docs/NUXT_MIGRATION.md` and `README.md`. The protocol, policy, audit and storage decisions below are unchanged; decisions about the admin UI and its web security are superseded by the migration document.

Binding for v2. Inherits DESIGN_V0/V1 and all earlier gates (284 tests must keep passing). Source: `docs/VERSION_PLAN.md` Version 2,
`docs/PRD.md` FR-17..19, NFR-R1..R3, §13 #12. Single-owner self-hosting; no HA, no clustering, no exactly-once claims.

## Decisions (resolves PRD §13 #12)
| # | Decision |
|---|---|
| Audit durability | Audit events are written to SQLite in the same request, **before the tool result is returned**. Default `AUDIT_FAIL_MODE=closed`: if the audit row cannot be written, the call fails with `UNAVAILABLE` and no data is returned (reads) / the write is not started. `open` is an explicit opt-in that logs to stderr instead. |
| Audit retention | `AUDIT_RETENTION_DAYS` (default 90, `0` = keep forever), pruned at startup and every 24 h. Export: admin UI `/audit` (filter + download JSONL/CSV) and `npm run audit:export -- --from --to --format`. Timestamps ISO-8601 UTC with ms (`...Z`); the UI labels the browser's local zone. |
| Audit content | Never bodies, header text, subjects, addresses, tokens, credentials. Message identity = mailbox + folder + uidValidity + uid(s). Multi-message reads/searches store the **exact returned UID set** (JSON array, capped at 5000 with `uids_truncated=1` flag). Message ids/access history are sensitive: file perms 0600, documented. |
| Logging | Structured JSON lines to stdout (`src/log.ts`), levels via `LOG_LEVEL`, central redaction (bearer tokens, `Authorization`, `password`/`pass`, `secret`, `token`, authorization codes, anything matching the master key / SESSION_SECRET values). All code logs through it; no `console.*` in src/ except via log.ts. |
| Process safety | `unhandledRejection`/`uncaughtException` handlers log (redacted) and keep serving for rejections; for uncaught exceptions they log, close gracefully and exit non-zero so the supervisor restarts. A failed tool call never terminates the process. |
| Timeouts | Every upstream tool operation ≤ 30 s total (budget including retries). Only an explicit background sync job (sidecar `sync` driven by the internal reconciler/IDLE, not a tool call) may exceed it (cap 300 s). |
| Retries | Read-only operations: max 2 retries inside the 30 s budget, jittered. **Writes are never automatically replayed.** |
| Request IDs | One UUID per MCP HTTP request (also honors incoming `X-Request-Id` if it matches `^[A-Za-z0-9_-]{8,64}$`), returned in tool error payloads (`requestId`), in the `X-Request-Id` response header, in logs and in the audit row. |
| IDLE | Sidecar IDLEs on INBOX + any folder with a warm cache; renews every `IDLE_RENEW_SECS` (default 1500 = 25 min; provider deadline is typically 29–30 min); untagged EXISTS/EXPUNGE/FETCH marks the folder stale and triggers an incremental sync. If the server lacks IDLE, fall back to polling every 60 s. |
| Backoff | Reconnect delay = `min(60s, 1s * 2^n)` with **full jitter** (`random(0, delay)` but never below 500 ms); reset after a connection stays healthy ≥ 30 s. Env for tests only: `RECONNECT_INITIAL_MS`, `RECONNECT_MAX_MS`. Resume within 90 s after connectivity returns (cap 60 s + connect/login) and run a full reconcile (`sync mode:"full"`) on every re-established connection. |
| Auth failures | Server rejects LOGIN/AUTHENTICATE (`AUTHENTICATIONFAILED`, `NO ... [AUTH...]`, generic `NO` on login) ⇒ mailbox `status='auth_failed'`; **all automatic credential attempts for that mailbox stop** (sidecar and Node pool). Resumes only after an admin edits the credentials or presses "Retry" in the UI (which resets status to `unknown`). Tools answer `AUTH_FAILED` immediately without contacting the server. |
| Health endpoints | `GET /healthz` = liveness (200 `{"status":"ok"}` if the process is serving). `GET /readyz` = readiness: DB read OK, master key loads and round-trips a test vector, sidecar ping OK (or `SIDECAR_DISABLED`), migrations applied; 200/503 JSON `{status, checks:{db,key,sidecar,migrations}}` — no hostnames/ids/secrets. Both unauthenticated, rate-limited, `Cache-Control: no-store`. Per-mailbox state is shown only in the authenticated admin UI. |
| Migrations & upgrades | Before applying pending drizzle migrations, copy the DB with `VACUUM INTO 'DATA_DIR/backups/bridge-<ISO>-pre-<n>.db'` (0600, keep last 5). A failed migration aborts startup with a clear error and leaves the original untouched. `docs/UPGRADING.md` documents roll-forward and restore-from-backup. |

## Error taxonomy (extends v0/v1; documented in `docs/ERRORS.md`)
Tool error payload: `{code, message, requestId, retryable: boolean, operatorAction?: string}`; no hostnames, usernames, server text or stack.
`FORBIDDEN, NOT_FOUND, STALE_REFERENCE, INVALID_INPUT, UNSUPPORTED, UPSTREAM_ERROR, UNKNOWN_OUTCOME` (existing) plus: `AUTH_FAILED` (mailbox credentials rejected; operatorAction), `TIMEOUT`, `QUOTA_EXCEEDED` (`OVERQUOTA`/`NO [LIMIT]`/full), `FOLDER_UNAVAILABLE` (mailbox exists but select denied/`UNAVAILABLE`, distinct from NOT_FOUND; **for policy-denied folders keep returning NOT_FOUND** — no oracle), `PROTOCOL_ERROR` (malformed server reply), `UNAVAILABLE` (our own subsystem down, e.g. audit store / sidecar unreachable). `retryable` true only for TIMEOUT/UPSTREAM_ERROR/UNAVAILABLE on reads.

## Mutation safety
- `create_draft` (APPEND): generate the Message-ID up front. If the connection drops / times out after the command was sent: reconnect (once, within the 30 s budget) and `UID SEARCH HEADER Message-ID <id>` in Drafts. Found ⇒ success with `reconciled:true` and the ref. Not found or cannot verify ⇒ `UNKNOWN_OUTCOME` (message says state unknown; never re-append).
- `move_message`: if ambiguous, verify: destination contains the Message-ID and source UID is gone ⇒ success `reconciled`; source still present and destination lacks it ⇒ report `UNKNOWN_OUTCOME` with `likelyNotApplied:true` (still not replayed); anything else ⇒ `UNKNOWN_OUTCOME`.
- `set_flags`: STORE is idempotent but still not auto-replayed; verify by re-FETCH of flags: matches desired ⇒ success `reconciled`; else per-message `UNKNOWN_OUTCOME`.
- Policy is rechecked before any reconcile read too (a revocation mid-failure must not read).

## Schema additions — migration `0002` (owner J generates with drizzle-kit)
```sql
CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,                 -- uuid
  ts TEXT NOT NULL,                    -- ISO-8601 UTC ms
  request_id TEXT NOT NULL,
  client_id TEXT,                      -- NULL for pre-auth failures
  mailbox_id TEXT, folder TEXT, uid_validity INTEGER,
  uid INTEGER,                         -- single-message ops
  uids TEXT, uids_truncated INTEGER NOT NULL DEFAULT 0,   -- JSON array for multi-message ops
  tool TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('ok','denied','failed','unknown_outcome')),
  error_code TEXT,                     -- tool error code when not ok
  cached INTEGER NOT NULL DEFAULT 0, reconciled INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER);
CREATE INDEX audit_ts ON audit_events(ts); CREATE INDEX audit_client ON audit_events(client_id, ts);
ALTER TABLE mailboxes ADD COLUMN status TEXT NOT NULL DEFAULT 'unknown';  -- unknown|ok|degraded|auth_failed
ALTER TABLE mailboxes ADD COLUMN last_error_code TEXT;
ALTER TABLE mailboxes ADD COLUMN last_ok_at TEXT;
ALTER TABLE mailboxes ADD COLUMN next_retry_at TEXT;
```
Every tool attempt writes exactly one row: allowed+succeeded (`ok`), policy-denied incl. NOT_FOUND-masked denials (`denied`), failed upstream/validation (`failed`), ambiguous write (`unknown_outcome`). Pre-tool auth failures (bad token) are **not** tool attempts (logged, not audited).

## Sidecar additions
New RPC `status {mailboxId}` => `{state:"connected"|"reconnecting"|"auth_failed"|"closed", since, lastErrorCode?, nextRetryAt?, idle:boolean, reconnects:number}`; `retry {mailboxId}` clears auth_failed latch (Node calls it after an admin edit/retry). Node polls `status` every 5 s for opened mailboxes and persists `mailboxes.status/last_error_code/last_ok_at/next_retry_at`.

## Workstreams (disjoint ownership)
- **I Reliability core** — `src/log.ts` (+ migrate all `console.*` in src/), `src/mcp/errors.ts`, `src/mcp/tools.ts`, `src/mcp/backend*.ts`, `src/imap/client.ts` (backoff, auth_failed latch via `markMailboxAuthFailed`, 30 s budget, read-retry, reconcile for the three writes), process handlers (`src/process.ts` imported from index by L), `docs/ERRORS.md`. Calls `auditNote()` from `src/audit/context.ts` in tools.
- **J Audit** — `src/audit/**` (store, wrapper `withAudit`, retention pruner, export lib, `audit:export` CLI, UI router `src/audit/routes.ts` exporting `auditRouter`), `src/mcp/server.ts` (wrap every tool, request id, fail-closed mode), `src/db/schema.ts` + `drizzle/0002_*` (both audit table and mailbox status columns), request-id middleware `src/security/requestId.ts`, mailbox status banner/retry button in `src/web/**`.
- **K Sidecar resilience** — `sidecar/**` (IDLE watchers + renewal + polling fallback, reconnect with backoff/jitter, auth latch, `status`/`retry` RPC, forced full reconcile on reconnect, Go tests with `testimap` fault injection), `src/sidecar/**` (status poller → mailboxes columns, retry call, passing env knobs).
- **L Ops** — `src/index.ts` (mount `auditRouter`, health routes, process handlers, audit pruner start), `src/health.ts`, `src/db/database.ts` (pre-migration backup), `Dockerfile`, `docker-compose.yml` (+ healthcheck), `deploy/Caddyfile.example`, `deploy/nginx.conf.example`, `docs/INSTALL.md`, `docs/UPGRADING.md`, `docs/TROUBLESHOOTING.md`, `docs/RECOVERY.md`, `.env.example`, `scripts/smoke.sh` + `test/smoke/**` (docker-based automated smoke: build image, start with fixture IMAP, healthz/readyz, bootstrap, OAuth+tool call, restart persistence, upgrade with new migration, missing/wrong key fail closed).
- **M Failure-injection tests & threat model** — `test/integration/v2-*.test.ts`, extend `test/helpers/fakeImap.ts` (fault hooks: reject login, per-command delay/hang, drop connection after N bytes / after command received, malformed reply, `NO [OVERQUOTA]`, folder SELECT `NO [UNAVAILABLE]`, IDLE drop, server-side auto-logout), `docs/THREAT_MODEL.md` v2 section, `docs/BENCHMARKS.md` untouched.

Rules: agents never `git commit`; never edit outside ownership (report needs); `npm run build` + `npm test` green at the end; peers land concurrently so code to this contract and re-check peer files; report real bugs in peers rather than weakening tests; all numbers measured, not asserted.
