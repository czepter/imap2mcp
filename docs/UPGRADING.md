# Upgrading, migrations and rollback

## What happens at startup

On every start the bridge compares the migrations shipped in the image (`drizzle/`) with those recorded in the database.

1. **Nothing pending**: no backup, normal start.
2. **Pending migrations on an existing database**: *before* anything is changed, the bridge writes a consistent copy with SQLite `VACUUM INTO` to

   ```
   DATA_DIR/backups/bridge-<ISO timestamp>-pre-<n>.db
   ```

   `<n>` is the number of migrations the database had already applied (so `pre-2` means "state before migration #3 ran"). The directory is mode 0700 and the file 0600. The newest 5 such files are kept; older ones are deleted automatically. Files you create yourself with other names are never pruned.
3. The migrations then run in a single transaction. **If one fails, the transaction rolls back, the process logs a `FATAL` error containing "Database migration failed" and the cause, and exits non-zero**; the original database is unchanged. With Compose's `restart: unless-stopped` the container then restarts in a loop; stop it (`docker compose stop`) and fix the cause.
4. If the backup itself cannot be written (disk full, directory not writable), startup aborts rather than migrating without a safety copy.
5. A fresh, empty database is created without a backup (there is nothing to protect).

`GET /readyz` reports `"migrations":"fail"` (503) if any migration shipped in the running build is not applied.

The migrations are resolved from `drizzle/` in the image (next to `.output/`, working directory `/app`). This behavior is exercised by `npm run smoke` (old database -> upgraded image: backup present, 0600, pre-migration contents, data and encrypted secrets intact; and a deliberately conflicting migration: abort, database unchanged).

## Upgrade procedure (roll-forward)

```bash
cd imap2mcp
# 1. Take your own backup first (see "Manual backup" below), and make sure the master key is backed up separately.
# 2. Keep the running image as a fallback, then fetch and rebuild
docker tag imap2mcp:local imap2mcp:prev      # "imap2mcp:local" is the image name in docker-compose.yml
git pull                                     # needs a checked-out branch (see below)
docker compose build
# 3. Replace the container; it migrates on start
docker compose up -d
# 4. Verify
docker compose ps                            # healthy
curl -s http://127.0.0.1:3000/readyz         # all checks "ok"
docker compose logs --tail 20 imap-bridge    # look for "pre-migration backup written" when migrations ran
ls -l data/backups                           # the automatic pre-migration copy
```

Then connect a client and run `list_folders` as a last check. Mailbox secrets, OAuth clients, grants and tokens survive upgrades; audit history is kept (subject to `AUDIT_RETENTION_DAYS`).

Upgrades are **roll-forward**. A database that has been migrated by a newer build is not guaranteed to work with an older image.

- `git pull` only works on a branch. After `git checkout <tag or commit>` you are on a detached HEAD and `git pull` fails with "You are not currently on a branch"; run `git checkout main` first (or `git fetch --tags` and check out the new tag).
- For production, pin to a release tag instead of tracking `main`: `git fetch --tags && git checkout <tag>`. This repository does not publish release tags yet; until it does, pin to a commit hash and record it.

## Upgrading from the Express-based release to the Nuxt release

The web UI and server were rebuilt on Nuxt 4 / Nitro (a single-page admin UI at the same URLs). What changes for an operator:

- **No database change.** The release adds no migration, so the first start runs no backup and no migration step. The machine-facing endpoints (`/mcp`, `/oauth/*`, `/.well-known/*`, `/healthz`, `/readyz`) keep their paths and behavior; issued OAuth tokens and registered clients keep working.
- **Admin sessions end once.** The session cookie keeps its name (`imap2mcp.sid`) but is now a sealed cookie instead of an id into an in-memory store, so the old cookie is not accepted: sign in again after the upgrade. From then on a restart no longer signs you out.
- **Entrypoint.** The image starts `node .output/server/index.mjs` (it was `node dist/index.js`) and still listens on `PORT` (default 3000). A `command:` or `entrypoint:` override in your own compose file must be updated; the stock `docker-compose.yml` needs no change. The audit export is still `node dist/audit/cli.js`.
- **Rollback** to the Express image is possible with the same database, because no migration was added; admin sessions end again.

## Manual backup (online)

The container has no `sqlite3` binary; use the bundled Node module. This takes a consistent snapshot while the server is running:

```bash
docker compose exec -T imap-bridge node -e "
const D=require('better-sqlite3'),fs=require('fs');
const db=new D('/app/data/bridge.db');
console.log('integrity:',db.pragma('integrity_check',{simple:true}));
fs.mkdirSync('/app/data/backups',{recursive:true,mode:0o700});
const f='/app/data/backups/manual-'+new Date().toISOString().replace(/:/g,'-')+'.db';
db.exec(\"VACUUM INTO '\"+f+\"'\");fs.chmodSync(f,0o600);console.log(f);"
```

Copy it off the host. **Do not store the master key next to it.** A backup holds encrypted mailbox passwords, OAuth tokens (hashed), grants and the access audit (message ids are sensitive).

Alternatively stop the container (`docker compose stop`) and copy `data/bridge.db` together with any `bridge.db-wal` and `bridge.db-shm`. Do not copy `bridge.db` alone while the server runs.

## Rollback

There are three paths, from the least to the most destructive. Pick by what went wrong.

### A. Keep the new code, re-run the migrations (preferred when the data is the problem)

Use this when a migration failed or left the database in a bad state but the new code is what you want to run. The pre-migration copy is the state *before* the migration ran, and the new code simply migrates it again (taking a new backup first).

```bash
docker compose stop
ls -l data/backups                                  # pick the pre-migration file, e.g. bridge-<timestamp>-pre-<n>.db
mv data/bridge.db data/bridge.db.failed-$(date +%s) # keep the broken one for analysis
rm -f data/bridge.db-wal data/bridge.db-shm
cp data/backups/bridge-<timestamp>-pre-<n>.db data/bridge.db
chown 1000:1000 data/bridge.db                      # only needed if you ran cp as another user (use sudo)
docker compose up -d                                # same image: migrations run again
curl -s http://127.0.0.1:3000/readyz
```

### B. Go back to the previous code and its database

Use this when the new version misbehaves and you want the old one back. You need the previous image and a database it understands (the pre-migration copy).

```bash
docker compose stop
# restore the database exactly as in path A (mv / rm / cp / chown), then use the old image:
docker tag imap2mcp:prev imap2mcp:local             # the tag you saved before building
docker compose up -d                                # no --build: it must not rebuild over the old image
```

If you did not save `imap2mcp:prev`, rebuild from the old source: `git checkout <previous tag or commit> && docker compose build && docker compose up -d`. This can fail for old commits: the v1 Dockerfile installed production dependencies in the final stage without build tools, so when `better-sqlite3` has no prebuilt binary for the `node:22-slim` base image of that time, `npm ci` there tries to compile it and fails (no `python3`/`make`/`g++`). The current Dockerfile builds in a separate stage and copies only the traced runtime files into the final image; `better-sqlite3` 13 ships prebuilt binaries, so no compiler is needed in either stage. Prefer the saved image, or cherry-pick the current `Dockerfile` onto the old checkout. (Derived from comparing the two Dockerfiles; the old commit was not rebuilt here.)

### C. Restore only the data, keep whatever code is running

Same copy steps as A. Notes for any restore:

- The restored file must be used with the **same master key** it was written under. Data written between the backup and the restore is lost (including audit rows and tokens issued since).
- If the backup is older than a revocation you care about, review **Tokens** and **Clients** in the UI after restoring and revoke what should no longer work.
- If you restored the pre-migration file and keep the *new* code, the migrations simply run again (and take a new backup): that is path A.

## Notes

- Pin versions in production (a release tag once they exist, otherwise a commit hash) instead of tracking `main`.
- Changing `BASE_URL` is not an upgrade: it invalidates all tokens, clients must re-authorize.
- Restoring a database does not change the key: see RECOVERY.md for key problems.
