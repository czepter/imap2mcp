# Operations (Version 0)

## Deployment checklist

1. Run behind an HTTPS reverse proxy; set `BASE_URL` to the public https URL. The MCP resource (token audience) is `${BASE_URL}/mcp`; changing `BASE_URL` later invalidates every issued token (audience mismatch) and clients must re-authorize.
2. Create the master key outside the data directory and outside the image:
   ```bash
   openssl rand -hex 32 > secrets/imap2mcp_key && chmod 600 secrets/imap2mcp_key
   ```
   `docker-compose.yml` mounts it as a secret at `/run/secrets/imap2mcp_key` and sets `ENCRYPTION_KEY_FILE`. The file may contain 64 hex characters or a base64 32-byte key.
3. Set `SESSION_SECRET` (>= 32 characters) via your secret mechanism.
4. Make `data/` writable by uid 1000 (the container user) and persistent.
5. Start, read the bootstrap token from the log, finish `/setup` straight away.
6. Decide `REGISTRATION_MODE`: `dynamic` lets any client that can reach the server create an inert client record (it gets no access until you consent); `admin` removes that surface and you create clients in the UI.
7. If your mail server lives on a private address, list its exact host name in `ALLOW_PRIVATE_HOSTS`. IP literals are matched literally, so list `10.0.0.5` if you use that form.

## Startup behavior (fail closed)

The process exits with `FATAL: ...` and a non-zero code for: no key configured, unreadable key file, key not 32 bytes hex/base64, all-zero key, the placeholder key from older example files, missing or short `SESSION_SECRET`, invalid `REGISTRATION_MODE` or `BASE_URL`. A syntactically valid but **wrong** key does not stop startup; instead every mailbox operation fails (tools return `UPSTREAM_ERROR`, the connection test fails) and no IMAP login is attempted. If tools suddenly fail after a redeploy, check that the same key file is mounted.

## Key handling

- Keep the key separate from database backups. A backup that contains both defeats the encryption.
- Back up the key through a different channel than the data (password manager, secret store). Without it, saved mailbox passwords are unrecoverable; you would re-enter them in the UI (OAuth clients, grants and tokens are unaffected because they do not depend on the key).
- Rotation is not implemented in v0. Each stored secret has the form `v1:<keyId>:<iv>:<ciphertext>:<tag>`; `keyId` is the first 8 hex characters of `sha256(key)` and is there to support rotation later. Current workaround: change the key, then re-enter each mailbox password in the UI.

## Backup and restore

SQLite in WAL mode: do not copy only `bridge.db` while running. Either stop the container and copy `bridge.db` plus any `bridge.db-wal`/`-shm`, or take an online backup:

```bash
sqlite3 data/bridge.db ".backup 'backup/bridge-$(date +%F).db'"
```

Restore by putting the file at `DATA_DIR/bridge.db` with the matching key mounted and starting the server. Verify by running **Test connection** on each mailbox. A restore with a different key starts but cannot decrypt (see above). Restored databases bring back old token rows; revoke tokens in the UI if the backup is older than a revocation you care about. Restore time for large databases is **untested** in v0.

## Revoking access

- Remove a single permission: **Clients -> client -> Grants**. Applies to the next tool call, including already issued tokens.
- Kill one token: **Dashboard -> Active tokens -> Revoke**.
- Cut off a client completely: **Dashboard -> Disable** (also revokes its tokens).
- Remove a mailbox: **Mailbox -> Delete**. Grants cascade; mail on the server is untouched.
- Rotating the IMAP password at the provider: edit the mailbox and enter the new password (leave empty to keep the old one). Changing host, port or username clears the Drafts folder selection.

Token lifetimes: access 1 hour, refresh 30 days, authorization code 10 minutes.

## Logs

Stdout/stderr only. Contents: startup lines, the one-time bootstrap token (first run only), MCP internal errors. Tests assert that passwords, tokens, authorization codes, the master key and the session secret do not appear. v0 has no audit trail of tool calls. Treat the first-run log as sensitive until setup is complete.

## Upgrades

Schema changes are applied by the `schema_migrations` runner at startup. Back up before upgrading. Rolling back to an older version after a migration is not supported.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Container exits immediately with `FATAL: ...` | Missing/invalid key or `SESSION_SECRET`; the message names the variable. |
| `/setup` returns 404 | An admin already exists. There is deliberately no reset route. To reset the owner password, stop the server, `DELETE FROM admin;` in `bridge.db`, restart, and use the new bootstrap token from the log (this procedure is untested). |
| Connection test: "Host resolves to a private..." | Add the exact host name to `ALLOW_PRIVATE_HOSTS`. |
| Connection test: "TLS certificate validation failed" | The server certificate is not trusted for that host name. Fix the certificate or, for a private CA, start the server with `NODE_EXTRA_CA_CERTS=/path/ca.pem`. Validation cannot be turned off. |
| Authentication failed | Wrong password, or the provider needs an app password / IMAP enabled. |
| All tools fail after a redeploy | Wrong or missing master key file, or `BASE_URL` changed (tokens invalid -> 401 and clients re-authorize). |
| Client gets `FORBIDDEN` on everything | No grants for that client, or the token was consented without that capability. Edit grants; for a capability beyond the token's scopes the client must authorize again. |
| `UNKNOWN_OUTCOME` from `create_draft` / `move_message` | A write may or may not have reached the server. Check the Drafts or target folder before retrying; the server never retries writes itself. |
| `STALE_REFERENCE` | The folder's UIDVALIDITY changed. Search again to get fresh references. |
| 429 on login or token endpoint | In-memory rate limit; wait or restart the process. |
