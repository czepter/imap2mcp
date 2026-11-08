# Tool error codes

Every failed MCP tool call returns `isError: true` with one JSON text payload:

```json
{ "code": "AUTH_FAILED", "message": "...", "requestId": "…", "retryable": false, "operatorAction": "..." }
```

- `requestId` is the id of the MCP HTTP request (also in the `X-Request-Id` response header, the logs and the audit row). Quote it when asking the operator for help.
- `retryable` is `true` only for `TIMEOUT`, `UPSTREAM_ERROR` and `UNAVAILABLE` **on read operations**. Writes (`create_draft`, `move_message`, `set_flags`) are never marked retryable and are never replayed automatically by the bridge.
- `operatorAction` (when present) tells the person running the bridge what to do. Agents should relay it, not act on it.
- Messages never contain hostnames, usernames, server text or stack traces.
- Some codes carry extra fields (`messageId` on `create_draft` `UNKNOWN_OUTCOME`, `likelyNotApplied` on `move_message`).

All upstream operations of one tool call share a **30 s total budget** (retries and reconciliation included). Read-only operations are retried at most twice with jitter inside that budget.

| Code | When it occurs | Retryable | Operator action |
|---|---|---|---|
| `FORBIDDEN` | The token has no grant that reaches the mailbox/operation, or the mailbox is unknown (indistinguishable on purpose). | no | Grant the capability to the client in the admin UI if it was intended. |
| `NOT_FOUND` | The folder does not exist **or the folder is denied by policy** (no existence oracle), or the message UID no longer exists. | no | None. If unexpected, check the client's folder rules. |
| `STALE_REFERENCE` | The `uidValidity` in a message ref no longer matches the folder (folder was recreated/renumbered). | no | None; search again to obtain fresh refs. |
| `INVALID_INPUT` | Bad arguments (date format, cursor, flags, missing Drafts folder configuration, batch size). | no | If "No Drafts folder is configured", set it in the admin UI. |
| `UNSUPPORTED` | The server supports neither `MOVE` nor `UIDPLUS`, so a safe move is impossible. | no | Use a provider with UIDPLUS or MOVE. |
| `UPSTREAM_ERROR` | The mail server is unreachable, refused the connection, a reconnect backoff is in effect, or an unclassified upstream failure. | yes (reads) | Check connectivity/provider status; the bridge reconnects automatically with capped exponential backoff (1 s … 60 s, full jitter). |
| `UNKNOWN_OUTCOME` | A write may or may not have been applied (connection dropped/timed out after the command was sent) and **could not be verified**. The write is not retried. See "Write safety" below. | no | Check the mailbox (Drafts folder / source and destination folders) before repeating the operation. |
| `AUTH_FAILED` | The server rejected the mailbox credentials (`AUTHENTICATIONFAILED`, `NO [AUTH…]`, failed LOGIN). The mailbox is latched `auth_failed`: all credential attempts stop and tools answer this code immediately **without contacting the server**. | no | Fix the password at the provider/in the admin UI, then edit the mailbox or press **Retry** (resets status to `unknown`). |
| `TIMEOUT` | The 30 s tool budget or an upstream deadline elapsed. For writes this becomes `UNKNOWN_OUTCOME` instead. | yes (reads) | If persistent, check provider latency and the sidecar logs. |
| `QUOTA_EXCEEDED` | The server answered `NO [OVERQUOTA]`, `NO [LIMIT]` or reports the mailbox full. The write was **not** applied. | no | Free space or raise the quota at the provider. |
| `FOLDER_UNAVAILABLE` | The folder exists but the server refused or could not select it (`NO [UNAVAILABLE]`, `NO [NOPERM]`). Distinct from `NOT_FOUND`. Policy-denied folders never return this code. | no | Check the folder's availability/permissions at the provider; try again later. |
| `PROTOCOL_ERROR` | The server sent a malformed or unparseable reply to a read. (For a write, a malformed reply is `UNKNOWN_OUTCOME`.) | no | Check provider status and bridge logs for the `requestId`; report if reproducible. |
| `UNAVAILABLE` | A bridge subsystem is down: the mail sidecar is unreachable/restarting, or the audit store could not be written while `AUDIT_FAIL_MODE=closed` (no data is returned / the write is not started). | yes (reads) | Check `/readyz`, the sidecar process, disk space and permissions of the data directory. |

## Write safety (no automatic replay)

`create_draft`, `move_message` and `set_flags` are sent at most once. If the connection fails after the command was sent, the bridge reconnects **once** inside the 30 s budget and verifies the result, after re-checking the client's policy (a revocation in the meantime means no verification read is made):

| Tool | Verification | Result |
|---|---|---|
| `create_draft` | `UID SEARCH HEADER Message-ID <generated id>` in the Drafts folder | found: success with `reconciled: true` and the ref; not found or not verifiable: `UNKNOWN_OUTCOME` (with `messageId`; the draft is never appended again) |
| `move_message` | destination searched by the source message's Message-ID; source UID checked | destination has it and the source UID is gone: success with `reconciled: true`; source still present and destination lacks it: `UNKNOWN_OUTCOME` with `likelyNotApplied: true`; anything else: `UNKNOWN_OUTCOME` |
| `set_flags` | re-`FETCH` flags | flags equal the desired state: that message is `ok` with `reconciled: true`; otherwise that message is `UNKNOWN_OUTCOME` |

An explicit server refusal (`NO`/`BAD`, e.g. `NO [OVERQUOTA]`) is definitive: the write was not applied, the specific code is returned and no verification is attempted.

## Internals for operators

- Tool-level audit rows record `outcome` `ok`, `denied`, `failed` or `unknown_outcome`, plus `error_code` (one of the codes above), `cached` (data served from the sidecar's header cache) and `reconciled`.
- `markMailboxAuthFailed(mailboxId)` / `clearMailboxAuthFailure(mailboxId)` (`src/imap/client.ts`) set and clear the latch and keep `mailboxes.status` in sync.
- Test-only knobs: `RECONNECT_INITIAL_MS`, `RECONNECT_MAX_MS` (backoff schedule), `TOOL_BUDGET_MS` (per-call budget).
