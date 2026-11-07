# IMAP MCP Server — Version Plan

Four release gates: a coarse-grained working core, precise permissions and fast sync, production resilience, then multi-user operation. These are proposed acceptance targets, not claims about an existing implementation.

## Vision and principles

A self-hosted, open-source bridge that lets MCP clients read and organize IMAP mailboxes without exposing mailbox credentials to models.

1. Start small: a minimal mailbox-and-permissions UI, not a replacement email client.

2. Default deny; enforce authorization server-side on every operation, including cached results.

3. Keep MCP OAuth separate from upstream IMAP authentication; encrypted storage protects either mailbox passwords or provider refresh tokens.

4. Prefer an OSI-approved permissive project license, such as MIT or Apache-2.0; review dependencies before release.

## Version 0 — “grob gehalten” (coarse-grained)

**Goal:** Ship the smallest working Streamable HTTP IMAP MCP server with OAuth-authenticated clients, encrypted mailbox credentials, and editable coarse permissions.

**Non-goals:** Fine-grained folder rules, Go/Rust sidecar, performance guarantees, multi-user tenancy, SMTP sending, permanent deletion, full email composition UI, and universal provider OAuth integrations.

### Acceptance criteria

1. Transport and OAuth: an MCP client completes an OAuth authorization-code flow with PKCE and calls tools over Streamable HTTP; missing, expired, wrong-audience, or invalid tokens are rejected. HTTP Basic auth and pre-shared static API tokens cannot authorize MCP requests.

2. Mailbox setup: an administrator adds a TLS-enabled IMAP mailbox, tests connectivity, saves it, and reconnects after a restart through the minimal UI; certificate validation is enabled and no saved secret is displayed back.

3. Encrypted persistence: choose SQLite or PGLite; store IMAP secrets using authenticated encryption with the key outside the database. A database/WAL dump and application logs contain no plaintext secret; a missing or incorrect key fails closed.

4. Coarse rights: the UI edits each OAuth client's per-mailbox read, draft, and organize grants. A client × mailbox × operation test matrix proves default-deny behavior; a grant change affects the next tool call, including already-issued access tokens. Draft/organize rights do not implicitly grant reading.

5. Core tools: integration tests search and read messages, append a draft to the designated Drafts folder without sending, move a message, and set/clear flags. Sort/organize means explicit move/flag actions, not an autonomous classifier; read/search leaves unread state unchanged. Both source and destination must be authorized for moves.

## Version 1 — Precision and performance

**Goal:** Introduce fine-grained, revocable authorization and a Go or Rust IMAP sidecar that efficiently serves mailboxes containing at least 5,000 messages.

**Non-goals:** Multi-user tenancy, distributed caches, persistent body indexing, SMTP, and a universal full-text search latency guarantee; CONDSTORE/QRESYNC is stretch scope, not a release requirement.

### Acceptance criteria

1. Policy refinement: split grants by folder and operation (search, read headers/body, draft, move, flag), with explicit deny precedence. Tests cover denied search-result leakage, cached data, cross-folder moves, and client revocation; revocation blocks new tool calls within 5 seconds and rechecks authorization before pending writes.

2. Sidecar boundary: Go or Rust executes FETCH/SEARCH behind a local socket or authenticated private channel, never a public unauthenticated port. The MCP layer remains the policy authority; the in-memory cache holds UIDs and headers, not bodies, and a forced sidecar restart rebuilds it correctly.

3. Sync correctness: cache identity includes mailbox, folder, UIDVALIDITY, and UID. UIDNEXT guides new-message fetches; a UIDVALIDITY change invalidates the folder cache before reuse. Periodic UID/flag reconciliation detects expunges and flag changes—UIDNEXT alone is not treated as complete synchronization. Tests cover all three cases.

4. Performance gate: on a reproducible fixture with 10,000 messages, 2 KB average cached headers, 2 vCPU/2 GB RAM, and IMAP round-trip latency at most 20 ms, cold UID/header sync completes within 30 seconds; warm header listing/search returning at most 100 results has p95 at most 300 ms across 100 calls at concurrency 5. Sidecar RSS stays below 256 MB; body transfer and remote body search are measured separately.

5. Incremental gate: under the same fixture, 100 new messages become searchable within 5 seconds after a sync starts; unchanged messages are not fully re-FETCHed. Flag/expunge reconciliation finishes within 60 seconds, and a UIDVALIDITY reset rebuilds within the cold-sync budget without serving stale UID mappings.

## Version 2 — Production hardening

**Goal:** Make single-owner self-hosting resilient, diagnosable, and auditable under routine provider and network failures.

**Non-goals:** High-availability clustering, multi-region service, compliance certification, multi-user tenancy, and guaranteed exactly-once execution across IMAP network failures.

### Acceptance criteria

1. Failure contracts: injected authentication failures, timeouts, malformed replies, quota errors, and unavailable folders produce documented structured errors, with no secret leakage or unhandled process termination; upstream tool operations time out within 30 seconds unless an explicit longer sync job is requested.

2. Recovery: simulated connection and IDLE drops trigger capped exponential backoff with jitter (1-second initial delay, 60-second cap); IDLE is renewed before the provider deadline. After connectivity returns, a mailbox resumes within 90 seconds and reconciles missed changes; authentication failures stop automatic credential retries and request operator action.

3. Mutation safety: disconnect tests during draft append, move, and flag operations never blindly replay an ambiguous write. The server reports an unknown outcome or reconciles server state first; read-only retries remain bounded.

4. Auditability: every tool attempt records timestamp, OAuth client, mailbox, folder, UIDVALIDITY/UID where applicable, tool, outcome, and request ID; multi-message reads/searches record the exact returned UID set. Tests verify allowed, denied, cached, and failed paths; bodies, headers, tokens, and credentials are excluded. Retention and log export are configurable.

5. Self-hosting gate: a tester using a clean host completes the documented container installation, TLS/reverse proxy and OAuth setup, external key provisioning, upgrades/migrations, health checks, and failure-recovery procedure without undocumented steps; automated smoke tests verify the resulting deployment.

## Version 3 — Ecosystem and scale

**Goal:** Support isolated users and recoverable encrypted deployments, with SMTP sending possibly added as a separately authorized capability.

**Non-goals:** Mandatory SMTP, a full webmail suite, shared/team mailboxes, cross-region HA, and Internet-scale hosted service operations.

### Acceptance criteria

1. Tenant isolation: two users can independently manage mailboxes and OAuth-client grants; adversarial tests using another user's mailbox, folder, message, grant, and cache identifiers return no cross-user data and cannot modify another user's state.

2. Bounded scale: on a documented 4 vCPU/8 GB host, 10 users with one 5,000-message mailbox each complete a 60-minute mixed read/search/flag test at aggregate concurrency 20 with under 1% unexpected errors and warm metadata-tool p95 below 1 second; per-user connection and concurrency limits prevent one user from exhausting all capacity.

3. Recoverable encrypted backups: produce a transaction-consistent backup covering database, grants, users, and encryption metadata, plus a documented separately protected key-recovery package. On a clean host, restoring a test database up to 1 GB takes at most 15 minutes and restores mailbox access and grants; absent/wrong keys and corrupted backups fail explicitly. Plaintext keys never accompany the database backup.

4. Key lifecycle: a tested rotation rewraps or re-encrypts every stored secret, survives interruption without data loss, and documents which older backups require old keys. Restored deployments invalidate pre-restore MCP sessions/tokens or document and test an equivalent forced reauthorization boundary.

5. Optional SMTP gate: if included, sending is disabled by default and requires an independent send grant plus explicit approval bound to recipient, subject, body, and attachments. Tests prove draft permission cannot send, denial sends nothing, and an ambiguous SMTP response is not blindly retried; if omitted, the release explicitly lists sending as unsupported.

## Cross-version decisions

1. Choose SQLite or PGLite and one authenticated-encryption scheme in v0; record the threat model. At-rest encryption protects copied storage, not a compromised running host. Provision the master key via an external secret mount; losing both key and recovery material means losing access to stored secrets.

2. Carry forward OAuth client IDs, mailbox IDs, policy schema versions, and stable tool contracts. V1 migrates each v0 grant to equivalent folder/operation rules without widening access; migration tests compare effective rights before and after.

3. Separate authorization from cache and transport; retain default-deny checks through every release. Email content is untrusted model input, never permission to broaden access or send mail.

4. Publish the benchmark fixture, command, machine limits, and results with each performance gate. Targets are engineering budgets, not promises across all providers; benchmark changes require an explicit decision.

5. Each version inherits earlier security and functional gates. Versions are scope gates rather than calendar commitments; defer stretch features rather than weakening acceptance criteria.

> **Release boundary:** Version 0 is deliberately coarse-grained, not authentication-free or plaintext-at-rest; later versions deepen policy, performance, resilience, and tenancy without discarding those foundations.
