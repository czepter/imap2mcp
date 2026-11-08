# Installation (clean host, container)

This is the complete path from an empty Linux host to a working, TLS-fronted bridge that an MCP client can use. Every command below was run against the image built from this repository. Anything not exercised is marked.

## 1. Prerequisites

| Need | Notes |
|---|---|
| Linux host, 1 vCPU / 512 MB is enough for one mailbox | Any distribution that runs Docker. |
| Docker Engine with the Compose v2 plugin (`docker compose version`) | The image is built on the host: it needs outbound internet for `npm`, Go modules and `apt` during `docker build`. Tested with Docker 29. |
| `openssl` and `git` | To generate secrets and fetch the source. |
| A DNS name pointing at the host, ports 80 and 443 open | For TLS. The name becomes `BASE_URL`. |
| Outbound TCP to your mail server's IMAPS port (993) | TLS only; there is no plaintext fallback. |
| An IMAP account (host, port, user, password or app password) | Password login only (XOAUTH2 is on the backlog). |

## 2. Get the code and build

```bash
git clone <this repo> imap2mcp && cd imap2mcp
docker compose build           # first build takes a few minutes (compiles the Go sidecar and better-sqlite3)
```

The image runs as the non-root user `node` (uid 1000), keeps `dumb-init` as PID 1, contains the Go sidecar, and has a Docker `HEALTHCHECK` against `/healthz`.

## 3. Provision secrets and configuration

The **master key** encrypts mailbox passwords. It lives in a file outside the image and outside `data/`, so a copy of the database alone is useless.

```bash
mkdir -p secrets data
openssl rand -hex 32 > secrets/imap2mcp_key
chmod 600 secrets/imap2mcp_key
```

The container user (uid 1000) must be able to read the key and write `data/`. If you are logged in as uid 1000 (check with `id -u`) you are done; otherwise:

```bash
sudo chown 1000:1000 secrets/imap2mcp_key data
```

(An unreadable key shows up as `FATAL: Cannot read ENCRYPTION_KEY_FILE ... EACCES`; see TROUBLESHOOTING.)

**Back the key up now, through a different channel than the database** (password manager or secret store). Without it, stored mailbox passwords cannot be recovered (RECOVERY.md, "Lost master key").

Create `.env` next to `docker-compose.yml` (Compose reads it automatically):

```bash
cp .env.example .env
sed -i "s#^BASE_URL=.*#BASE_URL=https://mcp.example.com#" .env                      # your public https URL
sed -i "s#^SESSION_SECRET=.*#SESSION_SECRET=$(openssl rand -hex 32)#" .env
chmod 600 .env
```

`BASE_URL` decides the OAuth issuer and the token audience (`${BASE_URL}/mcp`). Choose it once; changing it later invalidates every issued token. With an `https://` URL the session cookie is `Secure`, HSTS is sent and exactly one proxy hop is trusted (step 5).

Other settings (`REGISTRATION_MODE`, `ALLOW_PRIVATE_HOSTS`, `LOG_LEVEL`, `AUDIT_*`, ...) are described in `docs/OPERATIONS.md`. If your mail server is on a private address (LAN, VPN), list its exact host name in `ALLOW_PRIVATE_HOSTS`.

## 4. Start and check health

```bash
docker compose up -d
docker compose ps                                     # STATUS becomes "Up ... (healthy)" within ~30 s
curl -s http://127.0.0.1:3000/healthz                 # {"status":"ok"}
curl -s http://127.0.0.1:3000/readyz                  # {"status":"ok","checks":{"db":"ok","key":"ok","sidecar":"ok","migrations":"ok"}}
```

(`HOST_PORT` in `.env` changes the published port; the compose file binds it to `127.0.0.1` only.)

- `/healthz` is liveness: the process is serving.
- `/readyz` is readiness: database readable, master key loads and decrypts a real stored secret when one exists, sidecar answers a ping, all migrations applied. `503` with the failing check set to `"fail"` otherwise. Both endpoints are unauthenticated, rate limited (120 requests per minute per client IP), uncached, and contain no host names, ids or secrets.

## 5. TLS and reverse proxy

Do not expose port 3000 directly. Put a TLS-terminating proxy in front and point it at `127.0.0.1:3000`. Ready-made examples:

- `deploy/Caddyfile.example` (Caddy 2; automatic certificates). Validated with `caddy validate`.
- `deploy/nginx.conf.example` (nginx; bring your own certificate, for example from certbot). Syntax-checked with `nginx -t` and exercised with a request through nginx 1.30 over HTTP/2: `/healthz`, OAuth metadata with `https://` URLs, and `/mcp` answering 401 without a token.

Requirements the examples already meet; keep them if you write your own:

1. Forward `X-Forwarded-For` and `X-Forwarded-Proto` and **overwrite** any client-supplied values. The app trusts exactly one hop (`trust proxy = 1`) when `BASE_URL` is https; with more proxies in a chain the client IP seen by the rate limiters would be wrong.
2. Do not buffer responses and allow long reads: MCP over Streamable HTTP may answer with `text/event-stream`. The examples set `flush_interval -1` (Caddy) and `proxy_buffering off` plus a 1 h read timeout (nginx).
3. Keep the host name equal to the host in `BASE_URL`.

Reload the proxy with its usual command (`sudo systemctl reload caddy` or `sudo nginx -t && sudo systemctl reload nginx`; not exercised here), then check from outside:

```bash
curl -s https://mcp.example.com/readyz
curl -s https://mcp.example.com/.well-known/oauth-authorization-server | head -c 200   # URLs start with https://
```

## 6. First-run bootstrap

On the first start without an admin the log shows a one-time token:

```bash
docker compose logs imap-bridge | grep -A1 "bootstrap token"
```

Open `https://mcp.example.com/setup`, paste the token and choose the admin password (at least 12 characters). After that `/setup` returns 404 permanently; there is no reset route (see RECOVERY.md for the offline procedure). To pick the token yourself, set `ADMIN_BOOTSTRAP_TOKEN` in `.env` before the first start and remove it afterwards. Treat the first-run log as sensitive until setup is done.

Sign in at `/login`.

## 7. Add a mailbox

1. **Mailboxes -> Add mailbox**: label, IMAP host, TLS port (usually 993), username, password (use an app password if your provider requires one).
2. On the mailbox page press **Test connection**. A success shows the server's folders.
3. Pick the **Drafts folder** and **Save Drafts folder**. `create_draft` only ever writes there; without it, draft grants are disabled.

If the test says the host resolves to a private address, add the exact host name to `ALLOW_PRIVATE_HOSTS` and restart. If it reports a certificate error, the server certificate must be valid for that host name; for a private CA mount the CA file into the container and set `NODE_EXTRA_CA_CERTS` and `SIDECAR_EXTRA_CA_FILE` to its in-container path (certificate validation cannot be switched off).

## 8. Connect an MCP client (OAuth)

Point the client at `https://mcp.example.com/mcp`. It must support MCP authorization (OAuth 2.1, PKCE S256, public client); see `docs/CLIENTS.md` for what has been verified and what has not.

- `REGISTRATION_MODE=dynamic` (default): the client registers itself, which creates an inert record with no access.
- `REGISTRATION_MODE=admin`: create the client under **Clients -> Add client** and give its `client_id` to the client.

On first connection the client sends you to `/oauth/authorize`. Log in if asked, then tick, per mailbox, what this client may do (read, draft, organize) and approve. Afterwards refine the rules per folder and operation under **Clients -> your client**, revoke grants or tokens at any time (effective on the next call).

Verify the whole chain end to end, for example with the MCP Inspector or your client's own connector UI: `list_mailboxes` returns the mailbox and `list_folders` returns its folders.

## 9. Operate

- Logs: `docker compose logs -f imap-bridge` (JSON lines).
- Access audit: **Audit log** in the admin UI, or `docker compose exec imap-bridge node dist/audit/cli.js --format csv`.
- Stop/restart gracefully: `docker compose stop` / `docker compose restart` (waits up to 20 s; exit code 0).
- Upgrade: `docs/UPGRADING.md`. Problems: `docs/TROUBLESHOOTING.md`, `docs/RECOVERY.md`.

## Automated check of this procedure

`npm run smoke` (`scripts/smoke.sh`) builds the image and runs it against a TLS fake IMAP server, covering health endpoints, bootstrap, OAuth plus an MCP tool call, restart persistence, the upgrade path with a pre-migration backup, a failing migration, and missing/wrong key behavior. It prints `SKIP: ...` and exits 0 if Docker is unavailable. It does not cover the reverse proxy or a public DNS/TLS setup.
