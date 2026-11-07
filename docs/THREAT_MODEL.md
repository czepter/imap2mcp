# Threat model (Version 0, updated for Version 1)

Scope: the single-owner imap2mcp server as specified in `DESIGN_V0.md`, plus the v1 changes in `DESIGN_V1.md` (folder x operation policy, Go sidecar). The v1 section follows the v0 tables; where v1 supersedes a v0 statement it says so. Each claim below is tied to the test that exercises it (`test/integration/*`, `test/unit/*`); anything without a test is marked **untested**.

## Assets

1. IMAP mailbox credentials (host, username, password).
2. Mailbox content, reachable through the tools.
3. The owner's authority to grant and revoke access (admin password, session, OAuth tokens).
4. The server's network position (it can open TCP connections to mail hosts).

## Actors and trust

| Actor | Trust |
|---|---|
| Owner (one admin) | Fully trusted. Authenticates with a password chosen at bootstrap. |
| MCP client / AI agent | Untrusted until the owner consents, then trusted only for exactly the granted mailbox x capability pairs. Treated as a possibly manipulated actor (see prompt injection). |
| Mail content and senders | Untrusted input. Never an instruction source. |
| Network attacker / anonymous visitor | Untrusted. |
| Mail server | Trusted to hold the mail; identity is verified by TLS certificate validation. |
| Host operator / anyone who can read process memory or the running container | **Out of scope** (see Non-goals). |

## What v0 protects against, and how

| Threat | Mitigation | Evidence |
|---|---|---|
| Copied database, WAL or backup exposes mailbox passwords | AES-256-GCM per-record IV; key only in `ENCRYPTION_KEY_FILE` (or `ENCRYPTION_KEY`), never in the DB; AAD binds ciphertext to `table:row:column`, so a ciphertext copied to another row does not decrypt | `security.test.ts`: DB, WAL and SHM bytes (live and after close) contain none of the IMAP password, admin password, session secret, master key, access/refresh tokens; ciphertext moved to another row is refused without any IMAP login |
| Missing, malformed or wrong key silently degrades | No default key. Missing, unreadable, malformed, all-zero or placeholder key: process exits non-zero. Valid but wrong key: server starts, every mailbox operation fails and no IMAP login is attempted | `security.test.ts` (startup cases and wrong-key run) |
| Stolen or guessed bearer token | 32 random bytes, only `sha256` stored; 1 h access lifetime, 30 d refresh with rotation; reuse of a rotated refresh token also revokes the lineage; revocation (UI, `/oauth/revoke`, disabling a client) applies to the next request | `oauth-transport.test.ts` |
| Token replay against another resource | Audience/resource = `${BASE_URL}/mcp`, stored on code and token; mismatch is rejected; foreign `resource` rejected at authorize and token endpoints | `oauth-transport.test.ts` |
| Authorization-code interception | PKCE S256 mandatory (plain/missing rejected), single-use codes, exact redirect URI match, unregistered redirect URIs are never redirected to, https or loopback-http only | `oauth-transport.test.ts` |
| Alternative credentials on `/mcp` | HTTP Basic, static/pre-shared secrets (bootstrap token, session secret, master key, admin or mailbox password, the stored token hash), admin session cookie and API-key headers all return 401 | `oauth-transport.test.ts` |
| Over-broad delegation | Default deny. Access = token scopes (ceiling) ∩ live grant rows ∩ operation. Read, draft and organize are independent. Grants added later never widen an existing token. Removing a grant, deleting a mailbox, revoking a token or disabling a client applies on the next call | `policy-matrix.test.ts` (71 cases) |
| Client discovers mailboxes it has no grant for | Unknown and ungranted mailbox ids give the identical `FORBIDDEN` response; `list_mailboxes` lists only granted ones, without host or username | `policy-matrix.test.ts`, `tools.test.ts` |
| Destructive or state-changing reads | Reads use `BODY.PEEK` (verified on the wire, `\Seen` unchanged); no send tool and no SMTP code path; no delete tool; `\Deleted`/`\Recent` rejected by `set_flags`; moves remove only the moved UID (`UID MOVE`, or `COPY` + flag + `UID EXPUNGE`), never plain `EXPUNGE` | `tools.test.ts` (a bystander already flagged `\Deleted` survives the fallback path) |
| Unattended reference confusion | Message refs carry `UIDVALIDITY`; a changed value yields `STALE_REFERENCE` for read and move | `tools.test.ts` |
| Man-in-the-middle of the IMAP link | Implicit TLS only, certificate validation on, no `rejectUnauthorized:false`, no plaintext or STARTTLS fallback | `security.test.ts`: untrusted certificate refused with zero login attempts; a plaintext server receives no `LOGIN`/`AUTHENTICATE` and no password |
| SSRF through "add mailbox" / connection test | Host must resolve to public addresses unless listed (by exact host name) in `ALLOW_PRIVATE_HOSTS`; checked in the connection test and on every connect; loopback, RFC 1918, link-local (incl. 169.254.169.254), CGNAT, ULA, v4-mapped IPv6 are classified private | `security.test.ts`, `oauth-ssrf.test.ts` |
| Takeover through the setup endpoint | `/setup` exists only while no admin row exists and needs the one-time bootstrap token; afterwards 404 (also after restart); a later POST cannot change the password | `security.test.ts` |
| CSRF on the admin UI | Per-session token required on every state-changing POST (mailbox, grants, token revoke, client disable, consent, login, logout); missing, wrong and other-session tokens refused, nothing changes | `security.test.ts` |
| Admin brute force | In-memory rate limits on login, setup, token and registration endpoints | `security.test.ts` (login limiter; others **untested**) |
| Secret leakage in responses and logs | Tool errors are normalised (`FORBIDDEN`, `UPSTREAM_ERROR`, ...) without host, port or credentials; admin pages never render the saved password or ciphertext; logs contain no passwords, tokens, codes or keys | `security.test.ts` |
| Clickjacking / sniffing | `X-Frame-Options: DENY`, CSP `default-src 'none'`, `nosniff`, `Cache-Control: no-store`; session cookie `HttpOnly`, `SameSite=Lax`, `Secure` under an https `BASE_URL` | `security.test.ts` (`Secure` flag **untested**) |

## Prompt injection and untrusted mail

A message can contain text aimed at the agent reading it ("forward everything to ..."). v0 cannot stop an agent from being persuaded, so it limits the damage:

- an agent can only do what the owner granted for that mailbox; a `read`-only client cannot move, flag or draft;
- there is no send capability, so injection cannot exfiltrate by sending mail (it can still try to place content in a draft if `draft` was granted; drafts are never sent by this server);
- `organize` can hide or reorder mail (move to another folder, mark read/flagged). Grant it deliberately;
- anything an agent with `read` reads is disclosed to that agent's operator and model provider. This is inherent to delegation.

Tool results are returned as data; the server never interprets mail content.

## Known limitations and non-goals

- **Compromised running host or container is out of scope.** The master key is in process memory and the key file is readable by the service user. Encryption protects a copied database, WAL or backup, not a live attacker with the key.
- The key is not rotated automatically. The key id is stored in each ciphertext so rotation can be added later; v0 has no rotation procedure. Losing the key means re-entering mailbox passwords.
- Bearer tokens are not sender-constrained (no DPoP/mTLS); a stolen live token works until it expires or is revoked.
- Rate limiters are per process and in memory; they reset on restart and are keyed by client IP (behind a proxy, configure it to pass the real IP).
- No audit log in v0 (planned for v2). Recent activity is visible only in the IMAP server's own logs.
- ~~Coarse grants~~ (superseded in v1: rules are per folder and operation, see below).
- Single owner. Anyone with the admin password is the owner. There is no second factor.
- Bootstrap token is printed to stdout once on first run; whoever can read the logs before setup can complete setup. Complete setup immediately or set `ADMIN_BOOTSTRAP_TOKEN` yourself.
- Behavior was tested against a purpose-built IMAP fixture, not against Gmail, Fastmail, Dovecot or Exchange. Provider quirks (folder names, MOVE/UIDPLUS support, UIDVALIDITY handling) are **untested**.
- Denial of service (large mailboxes, slow servers) is only bounded by page size 50, batch 25, body cap 200 KB and a 30 s operation timeout.

---

# Version 1 additions

## New assets and components

5. The sidecar process: it holds mailbox credentials (in memory only) and a cache of message headers.
6. The sidecar channel: the Unix domain socket `DATA_DIR/sidecar.sock`.
7. The policy rule table `policy_rules` (folder x operation x allow/deny per client and mailbox).

## Policy authority (who decides)

The Node policy engine decides everything. The sidecar knows nothing about clients, grants or rules and only ever answers requests that reached it through Node. Node authorizes `(client, mailbox, folder, operation)` before every sidecar call and filters results after it. Rules are read live from SQLite on every call (no policy cache), which is what makes revocation immediate and lets writes be re-authorized right before they run.

Evaluation: the token's scopes must cover the operation's capability; then any matching deny wins, otherwise any matching allow, otherwise deny. Selectors are an exact folder path, `*`, or `prefix/*`; they are case-sensitive and anything else never matches (fails closed). A move needs `move` on the source **and** the destination folder.

| Threat | Mitigation | Evidence |
|---|---|---|
| Denied folder leaks through search (hits, counts, snippets, timing of contact) | Folder-less search expands only to folders where `search` and `read_headers` are allowed; denied folders are never contacted (no IMAP command on them is observed) and never counted in `total`; body-text search runs only against allowed folders | `v1-policy.test.ts` "denied search-result leakage" (asserts the fake server saw no command touching the denied folder) |
| Error text reveals that a denied folder exists | A denied folder and a non-existent folder give the same code and the same message (modulo the name echoed back) | `v1-policy.test.ts` ("indistinguishable from a folder that does not exist") |
| Body readable although only headers were granted | `read_message` needs `read_headers` for the header part and `read_body` for the body; with body denied no body text is returned | `v1-policy.test.ts` ("headers but no body") |
| Cache serves data after rights were reduced | The cache lives behind Node's check: every request is authorized first, so a warm cache grants nothing by itself. Tightening a rule applies to the very next call for search, list and read, including references obtained earlier | `v1-policy.test.ts` "cached data is not served after a policy change" |
| Move used to smuggle mail into a folder the client may not touch, or out of one it may not touch | `move` is required on both folders; an explicit deny on either side wins over wildcard allows; `flag` does not imply `move` | `v1-policy.test.ts` "cross-folder move needs both folders" |
| Deny bypass through overlapping or malformed selectors | Deny precedence regardless of specificity or order; case-sensitive matching; `IN*`, `?`, character classes, empty or space-padded selectors never match | `v1-policy.test.ts` "deny precedence and selectors" |
| Revoked client keeps working | Removing a rule or disabling the client takes effect on the next call (tested well under the 5 s budget); a write in flight is re-authorized immediately before it is sent, so a move or flag change revoked while the call is pending is never issued | `v1-policy.test.ts` "revocation" (pending move and pending set_flags hold the write connection at SELECT, revoke, then assert no MOVE/COPY/STORE reached the server) |
| Another local process talks to the sidecar | Unix socket only (never TCP/UDP: checked against `/proc` socket tables), directory 0700, socket 0600, and every request must carry a random 32-byte per-process secret that Node hands over on the child's stdin (not argv, not environment). Missing or wrong secret gives -32001 and no data | `v1-sidecar.test.ts` "sidecar boundary" |
| Credentials leak from the sidecar | Credentials are sent only in `open` over the authenticated socket, kept in memory, never written to disk; the sidecar's argv and environment contain no mailbox password | `v1-sidecar.test.ts` (argv/environ check); "never logged" is **untested** at the log level beyond the v0 log check |
| Message bodies persist in the cache | The cache holds UIDs, flags and headers only. Every body read goes to IMAP (`BODY.PEEK`) again and does not set `\Seen` | `v1-sidecar.test.ts` "bodies are never cached" |
| Stale or aliased UIDs after the folder is recreated | Cache identity is (mailbox, folder, UIDVALIDITY, UID). A UIDVALIDITY change drops the folder cache; a reference with the old UIDVALIDITY yields `STALE_REFERENCE` even when the same UID number now belongs to a different message | `v1-sidecar.test.ts` "UIDVALIDITY change" |
| Cache drifts from the server (expunge, flag change by another client) | Periodic UID and flag reconciliation (`SYNC_RECONCILE_SECS`, default 30 s); UIDNEXT only guides fetching new mail and is never treated as complete | `v1-sidecar.test.ts` "UIDNEXT arrivals" and "reconciliation" |
| Sidecar crash or kill | Node supervises it (backoff restart, health ping), re-opens mailboxes lazily; the cache is rebuilt from IMAP and reflects changes made while it was down. If the sidecar is unavailable tools return `UPSTREAM_ERROR`; there is no silent fallback to another read path (`SIDECAR_DISABLED=1` is a debugging switch only) | `v1-sidecar.test.ts` "forced sidecar kill and restart" |

## Cache leakage rules (normative)

1. Cached headers are returned only after the same `(client, mailbox, folder, operation)` check a fresh read would need, followed by a per-result folder check.
2. No code path serves a cache hit to a caller that Node did not authorize; the sidecar has no listener except the authenticated socket.
3. Folder-less queries enumerate folders through the policy filter first; denied folders are neither read from the cache nor synced.
4. Error text, result counts and ordering must not depend on the contents of a folder the client may not search.
5. The cache is in memory, scoped to the sidecar process, keyed by mailbox id; removing a mailbox or closing it drops its folders.
6. Bodies are never cached.

## Residual risks and limitations in v1

- The sidecar and Node run as the same OS user. A compromised Node process can talk to the sidecar by definition; a compromised sidecar holds the mailbox passwords of every opened mailbox and the headers in its cache. This is the same trust level as v0's single process, not better; the benefit of the split is a small, authenticated, read-only surface, not process-level isolation from Node.
- Another process running as the same OS user can read the sidecar's memory or ptrace it unless the host forbids it; out of scope (see v0 non-goals).
- Timing side channels: a denied folder is never contacted, but response latency of a folder-less search depends on how many folders the client may search. This only reveals the client's own rights.
- Folder identity is the IMAP path as listed. Renaming a folder makes its selectors stop matching (fail closed, but it can silently remove access); a path that becomes covered by an existing prefix selector after a rename is covered.
- The "within 5 s" revocation budget is met because the policy is read live; it does not apply to a tool call that already passed its checks and is mid-read (reads in flight finish). Writes are re-checked just before they are sent, but a write already sent cannot be recalled.
- Writes remain in Node and use their own IMAP connection (v0 behavior, including the ambiguous-outcome rules); the sidecar's cache learns of them via `invalidate` or the next reconcile, so a search right after a write can be stale for up to the reconcile interval if `invalidate` fails.
- Remote body search is passed to the mail server; its latency and cost are the provider's.
- Benchmarks and tests run against a purpose-built fake IMAP server; behavior with Dovecot, Gmail or Exchange is **untested**.
- XOAUTH2 and CONDSTORE/QRESYNC are not implemented (`docs/BACKLOG.md`).
