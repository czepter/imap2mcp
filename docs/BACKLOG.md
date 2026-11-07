# Backlog

Items consciously not done, with the reason. Order is not priority.

## Deferred from v1

### XOAUTH2 for IMAP (PRD FR-12, "Should")
- **What**: authenticate to providers that disable app passwords (Gmail, Microsoft 365) with OAuth 2.0 access tokens via IMAP `AUTHENTICATE XOAUTH2`.
- **Why deferred**: it needs a second OAuth client role (this server would be an OAuth *client* of Google/Microsoft), provider app registration and verification, refresh-token storage with the same encrypt-at-rest guarantees, consent/redirect flows in the admin UI, and per-provider quirks that the fake IMAP fixture cannot validate. None of that is needed to meet any v1 acceptance criterion, and shipping it untested against the real providers would be a false assurance. v1 stays on password/app-password IMAP over implicit TLS.
- **Exit criteria**: tests against a mock token endpoint plus one real provider run by the owner; the sidecar receives short-lived access tokens in `open` (never refresh tokens); threat model updated for the new token store.

### CONDSTORE / QRESYNC (PRD FR-16, "Could")
- **What**: use `HIGHESTMODSEQ` / `CHANGEDSINCE` / `VANISHED` so reconciliation costs O(changes) instead of O(messages).
- **Why deferred**: the version plan marks it stretch scope, not a release requirement, and v1's explicit-reconcile approach (`UID SEARCH ALL` + `UID FETCH 1:* (FLAGS)` every `SYNC_RECONCILE_SECS`, 30 s by default) already meets the 60 s reconcile gate on the 10k fixture (see `docs/BENCHMARKS.md`). QRESYNC needs server support and `ENABLE`, behaves differently across providers (and the fake fixture implements neither), and a wrong modseq implementation silently serves stale or missing data, which is worse than a slower correct reconcile. UIDNEXT alone is never treated as complete, with or without CONDSTORE.
- **Exit criteria**: capability-gated (use only when advertised), full reconcile kept as the fallback and as a periodic safety net, fixture support for modseq and `VANISHED` so expunge/flag tests cover both paths.

## Known limits carried by v1 (not scheduled)
- Folder identity is the IMAP path as listed: renaming a folder makes its rule selectors stop matching (fails closed). Automatic rename tracking is not done.
- Cache is in memory only; after a sidecar restart the first read of each folder pays a cold sync (about 30 s budget per 10k messages). A persistent header cache would need its own at-rest protection and invalidation story.
- Remote body search (`searchText`) has no latency guarantee; it is a pass-through to the provider.
- Writes (move, flag, draft) stay in Node and open their own IMAP connection; the sidecar learns about them through `invalidate` or the next reconcile.
- No per-message or per-sender rules; policy is folder x operation only.
- Benchmarks use a purpose-built fake IMAP server, not Dovecot/Gmail/Exchange.
