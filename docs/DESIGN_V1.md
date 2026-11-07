# v1 Design Contract — Precision and performance

Binding for v1 work. Inherits `docs/DESIGN_V0.md` and every v0 gate (all 208 tests must keep passing or be
deliberately updated). Source: `docs/VERSION_PLAN.md` Version 1, `docs/PRD.md` FR-12..16, §10 v1.

## Decisions (resolves PRD §13 #8–11)
| # | Decision |
|---|---|
| Sidecar language | **Go** (go-imap v2 `github.com/emersion/go-imap/v2`). Module in `sidecar/`. No local Go install: build/test through Docker (`scripts/go.sh <args>` runs `golang:1.23-alpine` with the repo mounted; uses local `go` if present). |
| Execution split | Sidecar executes **read-only** IMAP: LIST, STATUS, FETCH (envelope/flags/size/internaldate and body), SEARCH. **Writes (APPEND, MOVE, STORE) stay in Node** (`src/imap/client.ts`, v0 behavior, ambiguous-write rules unchanged). After a Node write, Node calls sidecar `invalidate`. |
| Policy authority | Node policy engine decides everything. Node authorizes (mailbox, folder, op) **before** every sidecar call and filters results after. The sidecar knows nothing about clients/grants and never serves a request that did not come through Node. |
| Channel | Unix domain socket `DATA_DIR/sidecar.sock` (dir 0700, socket 0600), newline-delimited JSON-RPC 2.0. Node spawns the binary (env `SIDECAR_BIN`, default `sidecar/bin/sidecar`) and supervises it (restart w/ backoff, health ping). Authentication: Node generates a random 32-byte secret per sidecar process and passes it on the child's **stdin** (not argv/env); every request must carry it in `params.auth` (constant-time compare); wrong/missing => error -32001 and connection closed. Never listens on TCP. |
| Credentials | Node sends credentials only in `open`, over the authenticated socket; sidecar keeps them in memory only, never logs, never persists. Node also passes the SSRF-vetted IP + `servername` (same DNS-pinning as v0). Sidecar enforces TLS validation (system roots + `SIDECAR_EXTRA_CA_FILE` for tests). |
| Cache | In-memory only, per `(mailboxId, folder, uidValidity)`: map uid -> `{flags, envelope, size, internalDate}`. **No bodies** are cached. Cache identity always includes uidValidity. Rebuilt from IMAP after sidecar restart (Node re-`open`s lazily on `unknown mailbox` error). |
| Sync | Per folder: `STATUS (UIDVALIDITY UIDNEXT MESSAGES)`. UIDVALIDITY changed => drop folder cache, cold sync. Cold sync: `UID FETCH 1:* (UID FLAGS ENVELOPE RFC822.SIZE INTERNALDATE)` in chunks of 1000. Incremental: `UID FETCH <lastUid+1>:* (...)`. Reconcile (every `SYNC_RECONCILE_SECS`=30 and on demand when stale): `UID SEARCH ALL` => drop uids no longer present (expunges); `UID FETCH 1:* (FLAGS)` => update changed flags. UIDNEXT alone is never treated as complete. CONDSTORE/QRESYNC: **not implemented** (FR-16 Could; deferred). |
| Search | Header-level criteria (from, to, subject, since, before, flags seen/flagged/answered, min/max size) are answered **from the cache**. Body text criteria go to remote IMAP `UID SEARCH TEXT`. They are separate RPC methods/params and benchmarked separately. |
| XOAUTH2 (FR-12) | **Deferred** (Should). Not in v1 scope; recorded in `docs/BACKLOG.md`. |
| Limits | page size max 50 stays for the MCP tools; sidecar caps any result at 500. |

## Policy v1 (Node)
Operations: `search`, `read_headers`, `read_body`, `draft`, `move`, `flag`. Capability mapping (token ceiling, unchanged OAuth scopes): search/read_headers/read_body => `read`; draft => `draft`; move/flag => `organize`.
Rule table (new drizzle migration `0001`, replaces `grants`):
```
policy_rules(id TEXT PK, client_id FK cascade, mailbox_id FK cascade,
  folder TEXT NOT NULL,            -- exact IMAP path, or glob: '*' (all), 'INBOX/*' (prefix incl. sub-folders). case-sensitive. no other wildcards.
  operation TEXT NOT NULL CHECK in the 6 ops,
  effect TEXT NOT NULL CHECK in ('allow','deny'), created_at)
UNIQUE(client_id, mailbox_id, folder, operation)
```
Evaluation for `(client, mailbox, folder, op)`: token scopes must include the op's capability; then **any matching deny => deny; else any matching allow => allow; else deny**. Invalid selectors never match (fail closed). `draft` is evaluated against the mailbox's configured Drafts folder. `move` is checked separately for the source folder (`move`) AND the destination folder (`move`). Folder identity = IMAP path string as listed (rename => selector stops matching => fail closed; documented).
Policy API (`src/policy/policy.ts`, live DB read on every call, no cache — this is what satisfies "revocation blocks new calls within 5 s" and "recheck before pending writes"):
```ts
export type Operation = "search"|"read_headers"|"read_body"|"draft"|"move"|"flag";
export function assertOp(ctx, mailboxId, folder, op): void            // throws PolicyError
export function isOpAllowed(ctx, mailboxId, folder, op): boolean
export function filterAllowedFolders(ctx, mailboxId, ops: Operation[], folders: string[]): string[] // folders where ANY listed op allowed
export function anyAllowedMailboxes(ctx): string[]                    // mailboxes where ctx has any allow reaching a scope
```
v0 compatibility shims `assertAllowed/allowedMailboxes` stay exported (mapping to `folder="*"` semantics: allowed iff an allow rule exists with folder `*`... see migration) until all callers move; remove at end of v1.
**Migration (no widening):** v0 `read` => allow `{search,read_headers,read_body}` on `*`; `draft` => allow `draft` on `*` (effective: Drafts folder only, as in v0); `organize` => allow `{move,flag}` on `*`. Folder discovery (`list_folders`): v0 required `read`; v1 requires any of search/read_headers/read_body allowed on the folder, and returns only such folders (organize-only/draft-only clients get none, as in v0). A test computes effective rights for every (client, mailbox, folder-sample, op) before and after migration and asserts equality.
Leakage rules: search never touches or counts folders where `search` is denied; search results also require `read_headers` per result folder; `read_message` header portion needs `read_headers`, body needs `read_body` (tool returns headers only if body denied); cached data is returned only after the same checks; error messages never reveal whether a denied folder exists.

## MCP tool changes
Existing seven tools keep names and schemas (additive fields only). `search_messages`/`list` accept optional `folder` (omitted => all folders where search+read_headers allowed). `read_message` gets `include: ["headers","body"]` (default both, each subject to policy). Read paths use the sidecar; if the sidecar is unavailable, tools return `UPSTREAM_ERROR` (no silent fallback to unauthenticated paths; v0 direct path may remain behind `SIDECAR_DISABLED=1` for debugging only).

## Sidecar RPC (all requests `{jsonrpc:"2.0",id,method,params:{auth,...}}`)
| method | params | result |
|---|---|---|
| `ping` | – | `{version, uptimeSecs, rssBytes}` |
| `open` | `{mailboxId, host, ip, port, servername, user, pass}` | `{ok:true}` (idempotent; replaces creds) |
| `close` | `{mailboxId}` | `{ok:true}` |
| `listFolders` | `{mailboxId}` | `{folders:[{path, delimiter, flags[]}]}` |
| `sync` | `{mailboxId, folder, mode:"auto"\|"full"}` | `{uidValidity, uidNext, count, fetched, durationMs, reset:boolean}` |
| `list` | `{mailboxId, folder, limit, beforeUid?}` | `{uidValidity, items:[Header], nextBeforeUid?}` newest first |
| `search` | `{mailboxId, folder, criteria, limit, beforeUid?}` | same shape as list |
| `searchText` | `{mailboxId, folder, text, limit}` | remote IMAP search, `{uidValidity, uids:[...]}` |
| `fetchHeaders` | `{mailboxId, folder, uidValidity, uids[]}` | `{items:[Header]}`; stale uidValidity => error `STALE_REFERENCE` (-32010) |
| `fetchBody` | `{mailboxId, folder, uidValidity, uid, maxBytes}` | `{text, html?, truncated}` using BODY.PEEK |
| `invalidate` | `{mailboxId, folder?}` | `{ok:true}` marks stale; next call syncs |
| `stats` | – | cache sizes, last sync times |
`Header = {uid, uidValidity, flags[], subject, from[], to[], cc[], date, messageId, size}`. Errors use JSON-RPC error `{code,message}` with codes: -32001 auth, -32002 unknown mailbox (Node must `open` and retry once), -32010 stale ref, -32020 upstream error (message redacted of credentials), -32030 timeout. Per-request upstream timeout 30 s.

## Performance gate & harness (D)
Reproducible fixture: 10,000 messages, avg cached header ≈2 KB, IMAP RTT ≤20 ms (injected), sidecar limited to 2 vCPU/2 GB (`docker run --cpus=2 --memory=2g`). Harness in `bench/` (fake IMAP server with N messages + configurable latency, driver script), command `npm run bench`, results appended to `docs/BENCHMARKS.md` with machine info. Gates: cold sync ≤30 s; warm list/search ≤100 results p95 ≤300 ms over 100 calls at concurrency 5; sidecar RSS <256 MB; 100 new messages searchable ≤5 s after sync start without refetching unchanged; flag/expunge reconcile ≤60 s; UIDVALIDITY reset rebuild within cold budget with no stale mappings. **Report actual numbers; if a gate fails, say so — never tune the gate.**

## Workstreams (disjoint ownership)
- **E Policy & Admin UI** — `src/policy/**`, `src/db/schema.ts` + `drizzle/` (migration 0001 incl. data migration SQL), `src/web/**` (grant editor => rule editor: per client x mailbox presets expanding to rules + advanced rule list with allow/deny, folder selector, op; revoke client), `src/oauth/**` only where consent writes `grants` (consent now writes preset rules), policy unit tests + migration-equivalence test (`test/unit/policy-v1.test.ts`, `test/unit/migration-v1.test.ts`).
- **F Go sidecar** — `sidecar/**` (go.mod, cmd, internal packages, Go unit tests), `scripts/go.sh`, Dockerfile build stage for the binary. Includes an in-package test IMAP server or uses go-imap's `imapmemserver` for tests.
- **G Node integration** — `src/sidecar/**` (UDS client, spawn/supervise, auth handshake, restart+reopen), `src/mcp/**` read paths (list/search/read via sidecar with policy before+after), `src/imap/client.ts` write paths keep v0 behavior + call `invalidate`, recheck policy right before each write, `src/index.ts` lifecycle hooks (start/stop sidecar), config (`SIDECAR_BIN`, `SIDECAR_DISABLED`).
- **H Bench, tests, docs** — `bench/**`, `test/integration/**` (v1: leakage, cache, cross-folder move, revocation <5 s incl. pending writes, sidecar restart rebuild, UIDVALIDITY/UIDNEXT/expunge), extend `test/helpers/fakeImap.ts` (large mailboxes, latency, UIDVALIDITY change, external expunge/flag change), `docs/BENCHMARKS.md`, `docs/THREAT_MODEL.md` v1 update, `docs/BACKLOG.md`, README updates.

Agents never `git commit`; never edit outside their ownership (report instead). `npm run build` and `npm test` must work at the end; peers land concurrently, so code to this contract and re-check peer files before finalizing.
