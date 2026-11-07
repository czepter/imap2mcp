# Threat model (Version 0)

Scope: the single-owner imap2mcp server as specified in `DESIGN_V0.md`. Each claim below is tied to the test that exercises it (`test/integration/*`, `test/unit/*`); anything without a test is marked **untested**.

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
- Coarse grants: no per-folder or per-operation rules; `organize` includes moving to any existing folder of the mailbox (v1).
- Single owner. Anyone with the admin password is the owner. There is no second factor.
- Bootstrap token is printed to stdout once on first run; whoever can read the logs before setup can complete setup. Complete setup immediately or set `ADMIN_BOOTSTRAP_TOKEN` yourself.
- Behavior was tested against a purpose-built IMAP fixture, not against Gmail, Fastmail, Dovecot or Exchange. Provider quirks (folder names, MOVE/UIDPLUS support, UIDVALIDITY handling) are **untested**.
- Denial of service (large mailboxes, slow servers) is only bounded by page size 50, batch 25, body cap 200 KB and a 30 s operation timeout.
