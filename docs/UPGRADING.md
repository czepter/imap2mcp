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

This behavior is exercised by `npm run smoke` (old database -> upgraded image: backup present, 0600, pre-migration contents, data and encrypted secrets intact; and a deliberately conflicting migration: abort, database unchanged).

## Upgrade procedure (roll-forward)

```bash
cd imap2mcp
# 1. Take your own backup first (see "Manual backup" below), and make sure the master key is backed up separately.
# 2. Fetch and rebuild
git pull
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

## Rollback: restore from a backup

Use this when an upgrade went wrong and you want the previous data state back (you also need the previous code: `git checkout <previous tag or commit>` and `docker compose build`).

```bash
docker compose stop
ls -l data/backups                                  # pick the pre-migration file you want
mv data/bridge.db data/bridge.db.failed-$(date +%s) # keep the broken one for analysis
rm -f data/bridge.db-wal data/bridge.db-shm
cp data/backups/bridge-<timestamp>-pre-<n>.db data/bridge.db
chown 1000:1000 data/bridge.db                      # only needed if you ran cp as another user (use sudo)
git checkout <previous version>                     # code matching that database
docker compose build && docker compose up -d
curl -s http://127.0.0.1:3000/readyz
```

The restored file must be used with the **same master key** it was written under. Data written between the backup and the restore is lost (including audit rows and tokens issued since). If the backup is older than a revocation you care about, review **Tokens** and **Clients** in the UI after restoring and revoke what should no longer work. If you restored the pre-migration file and keep the *new* code, the migrations simply run again (and take a new backup).

## Notes

- Pin versions in production (`git checkout <tag>`) instead of tracking `main`.
- Changing `BASE_URL` is not an upgrade: it invalidates all tokens, clients must re-authorize.
- Restoring a database does not change the key: see RECOVERY.md for key problems.
