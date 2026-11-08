# Recovery procedures

All commands assume the Compose layout from `docs/INSTALL.md` (`imap2mcp/` with `data/`, `secrets/`, `.env`). Run `docker compose stop` before touching files in `data/`. Steps marked "verified" are exercised by `npm run smoke` or were run by hand against the built image; others are marked.

## Lost or wrong master key

Symptom: `/readyz` is 503 with `"key":"fail"`; tools fail for mailboxes whose password cannot be decrypted. The process still serves `/healthz` and the admin UI. The log contains no key material.

**If you have the original key** (password manager, secret store): put it back at `secrets/imap2mcp_key` (64 hex characters or base64, no other content) and `docker compose up -d`. Readiness returns to `ok` (verified).

**If the key is gone for good**, the stored mailbox passwords cannot be decrypted by anyone. OAuth clients, grants, policies, tokens and audit history do not depend on the key and are kept. Re-enter the passwords under a new key:

```bash
docker compose stop
mv secrets/imap2mcp_key secrets/imap2mcp_key.lost      # keep for comparison, then delete securely
openssl rand -hex 32 > secrets/imap2mcp_key && chmod 600 secrets/imap2mcp_key
docker compose up -d
```

1. Sign in. `/readyz` is 503 (`key: fail`) until every mailbox has been re-saved.
2. For each mailbox: **Mailboxes -> mailbox**, enter the IMAP password in the Connection form and **Save connection** (verified: this re-encrypts under the new key and `/readyz` returns to 200), then **Test connection**.
3. Back up the new key through a separate channel.

If you would rather start clean, delete the mailboxes in the UI and add them again.

## Corrupt database

Symptoms: `FATAL: database could not be opened or migrated` with `SQLITE_NOTADB`, `SQLITE_CORRUPT` or "malformed"; the container restart-loops (verified with a damaged file: the process exits at startup and nothing is modified).

1. `docker compose stop`.
2. Preserve the evidence: `mv data/bridge.db data/bridge.db.corrupt-$(date +%s); rm -f data/bridge.db-wal data/bridge.db-shm`.
3. Restore the newest good backup: `ls -l data/backups` (automatic `bridge-*-pre-*.db` copies from upgrades, plus your own manual ones; see UPGRADING.md), then `cp data/backups/<file> data/bridge.db` (add `chown 1000:1000 data/bridge.db` if you used another user).
4. `docker compose up -d`; check `/readyz` (verified).
5. Review **Tokens** and **Clients**: anything issued or revoked after the backup was taken is not reflected. Mailbox passwords come back as long as the same key is in place.

To check a database without starting the server (while stopped):

```bash
docker compose run --rm --no-deps --entrypoint node imap-bridge -e \
  "const D=require('better-sqlite3');console.log(new D('/app/data/bridge.db',{readonly:true}).pragma('integrity_check'))"
```

`integrity_check: 'ok'` means the file is structurally sound. With no usable backup, the only remedy is a new database: move `data/bridge.db*` away and start; you then repeat `/setup`, mailbox entry and client consent. SQLite-level salvage (`.recover`) needs the `sqlite3` CLI on the host and is not covered here.

## Restore a backup (any reason)

Same as steps 1 to 4 above, or see "Rollback" in UPGRADING.md if you also need to go back to older code. The key must match the backup. Restore time for very large databases is untested; a typical single-owner database is a few megabytes.

## Mailbox in `auth_failed`

Cause: the IMAP server rejected the login. The bridge stops all automatic credential attempts for that mailbox (to avoid provider lockouts) and tools return `AUTH_FAILED` without contacting the server.

1. Find out why at the provider: changed password, expired app password, IMAP disabled, account locked, new 2FA requirement.
2. Fix it there, then in the UI open **Mailboxes -> mailbox**: either enter the new password and **Save connection** (this also resumes attempts), or press **Retry** if nothing changed on your side.
3. Run **Test connection**. Status returns to `ok` on the next successful use.

## Sidecar down

Symptom: `/readyz` shows `"sidecar":"fail"`; read tools return errors.

- It is supervised: a crashed or killed sidecar is restarted automatically with backoff (verified: killed with SIGKILL, back within about a second, `/readyz` stayed `ok`).
- If it keeps failing: `docker compose logs imap-bridge | grep '"component":"sidecar"'`; verify `sidecar/bin/sidecar` is in the image (`docker compose exec imap-bridge ls -l sidecar/bin`) and `data/` is writable.
- A restart of the whole service rebuilds the sidecar's in-memory cache from IMAP: `docker compose restart imap-bridge`.
- Rebuilding the image fixes a damaged binary: `docker compose build --no-cache && docker compose up -d`.
- Diagnosis only: `SIDECAR_DISABLED=1` in the container environment uses the direct IMAP path (slower, no cache, no IDLE). Remove it afterwards.

## Reset the owner password (no UI access)

`/setup` is permanently 404 once an admin exists. Offline procedure (verified by hand against the built image):

```bash
docker compose stop
docker compose run --rm --no-deps --entrypoint node imap-bridge -e \
  "const D=require('better-sqlite3');new D('/app/data/bridge.db').exec('DELETE FROM admin')"
docker compose up -d && docker compose logs imap-bridge | grep -A1 "bootstrap token" | tail -2   # the newest token is the last one in the log
```

Then open `/setup` with the new token. Mailboxes, clients and grants are untouched.

## Everything lost (host gone)

You need: a database backup (optional but saves re-entry) and, separately, the master key. On the new host follow INSTALL.md, place the old `data/bridge.db` (as in "Restore a backup") and the old key at `secrets/imap2mcp_key`, keep the same `BASE_URL` (tokens are bound to it), and start. Without the database you reinstall fresh; clients must re-authorize.
