<img src="assets/icon.svg" width="64" height="64" alt="">

# imap2mcp

A single-owner bridge that lets AI agents use your IMAP mailboxes through the [Model Context Protocol](https://modelcontextprotocol.io/) (Streamable HTTP), with OAuth 2.1 authorization, encrypted mailbox credentials, and permissions you edit per client and per mailbox.

**Status: Version 0 ("grob gehalten", coarse-grained).** It is deliberately small. See `docs/VERSION_PLAN.md` for what v0 does and does not promise, `docs/PRD.md` for the product requirements, and `docs/DESIGN_V0.md` for the binding design contract.

## What it does

- **MCP over Streamable HTTP** at `${BASE_URL}/mcp`, stateless, bearer-token protected.
- **OAuth 2.1 authorization server**: authorization code with mandatory PKCE (S256), RFC 8414/9728 metadata, RFC 7591 dynamic client registration (or admin-created clients), RFC 8707 resource binding to `${BASE_URL}/mcp`, refresh-token rotation. HTTP Basic auth and static API tokens are not accepted anywhere on `/mcp`.
- **Three independent capabilities** per OAuth client and mailbox, edited in the admin UI. Nothing implies anything else.

  | Capability | OAuth scope | Tools |
  |---|---|---|
  | `read` | `mail:read` | `list_folders`, `search_messages`, `read_message` |
  | `draft` | `mail:draft` | `create_draft` (appends to the mailbox's configured Drafts folder only) |
  | `organize` | `mail:organize` | `move_message`, `set_flags` |

  `list_mailboxes` returns only mailboxes the client holds some grant for (id, label, capabilities; no hosts or usernames). Effective access on every call is the token's scopes **intersected with the live grant rows**, so removing a grant in the UI applies to the next call, including with an already issued token. Default is deny.
- **Mailbox secrets encrypted at rest** (AES-256-GCM, per-record IV, ciphertext bound to its table/row/column). The master key lives in a file outside the database. A missing or malformed key stops the server from starting; a wrong key makes every mailbox operation fail.
- **Safe IMAP behavior**: TLS only with certificate validation, no plaintext fallback; reads use `BODY.PEEK` so unread state is not changed; moves use `UID MOVE` or `UID COPY` plus flag and `UID EXPUNGE` of that UID only (never a plain `EXPUNGE`); `\Deleted` cannot be set through the tools.
- **SSRF policy**: a mailbox host must resolve to public addresses unless it is listed in `ALLOW_PRIVATE_HOSTS`.

## What it does not do (v0)

No sending (no SMTP at all), no permanent deletion, no folder-level or per-operation rules (v1), no persistent audit log (v2), no multi-user tenancy (v3), no key rotation tooling yet. Mail content is untrusted input: anything a client with `read` can read is exposed to that client and its model. See `docs/THREAT_MODEL.md`.

## Quick start (Docker Compose)

```bash
git clone <this repo> && cd imap2mcp

# 1. Master key: outside the database, never committed, never in the image.
mkdir -p secrets data
openssl rand -hex 32 > secrets/imap2mcp_key
chmod 600 secrets/imap2mcp_key
chown 1000:1000 data            # the container runs as uid 1000 ("node")

# 2. Required settings (no defaults for secrets).
export BASE_URL=https://mcp.example.com      # public URL; the MCP resource is $BASE_URL/mcp
export SESSION_SECRET=$(openssl rand -hex 32)
# optional:
# export REGISTRATION_MODE=admin            # default: dynamic
# export ALLOW_PRIVATE_HOSTS=mail.lan       # comma list of hosts allowed to resolve to private IPs

docker compose up -d --build

# 3. First run: the server prints a one-time bootstrap token to its log.
docker compose logs imap-bridge | grep -A1 "bootstrap token"
```

Then:

1. Open `${BASE_URL}/setup`, paste the bootstrap token and choose the admin password (min. 12 characters). After this, `/setup` returns 404 permanently. You can fix the token in advance with `ADMIN_BOOTSTRAP_TOKEN`.
2. Add a mailbox (host, TLS port, username, password), run **Test connection**, and pick the **Drafts folder** from the server's folder list.
3. Point your MCP client at `${BASE_URL}/mcp`. It discovers OAuth, registers, and sends you to the consent screen, where you tick exactly which mailbox x capability to allow. You can change grants any time under **Clients**, and revoke tokens under **Dashboard**.

Run it behind an HTTPS reverse proxy (the compose file binds `127.0.0.1:3000`). With an `https://` `BASE_URL` the session cookie is `Secure` and one proxy hop is trusted. See `docs/OPERATIONS.md` for backup, key handling and upgrades.

### Without Docker

```bash
npm ci
npm run build
export BASE_URL=http://localhost:3000 SESSION_SECRET=$(openssl rand -hex 32) \
       ENCRYPTION_KEY_FILE=$PWD/secrets/imap2mcp_key DATA_DIR=$PWD/data
npm start
```

Node 22 or newer. `ENCRYPTION_KEY` (64 hex characters) is accepted as an alternative to `ENCRYPTION_KEY_FILE`; the file is preferred because environment variables leak into process listings and crash dumps.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `BASE_URL` | yes for production | Public URL. MCP resource/audience is `${BASE_URL}/mcp`. `https` turns on `Secure` cookies and HSTS. |
| `ENCRYPTION_KEY_FILE` or `ENCRYPTION_KEY` | yes | 32-byte master key (hex or base64 in the file; 64 hex characters in the variable). No default. |
| `SESSION_SECRET` | yes | At least 32 characters. No default. |
| `DATA_DIR` | no | Directory of `bridge.db` (SQLite, WAL). Default `./data`. |
| `PORT` | no | Default 3000. |
| `REGISTRATION_MODE` | no | `dynamic` (default, RFC 7591; registration grants nothing) or `admin` (clients are created in the UI only). |
| `ALLOW_PRIVATE_HOSTS` | no | Comma list of mailbox host names that may resolve to private/loopback addresses. Matched by exact host name. |
| `ADMIN_BOOTSTRAP_TOKEN` | no | Fixed one-time bootstrap token instead of a random one. |
| `CORS_ORIGIN` | no | CORS origin for the machine-facing endpoints. |

## Tests

```bash
npm test                  # everything
npm run test:unit
npm run test:integration  # spawns the real server against an in-process IMAP-over-TLS fixture
```

The integration suite needs `openssl` (to create a self-signed certificate for the fixture, injected through `NODE_EXTRA_CA_CERTS` so certificate validation stays on). If it is missing, those tests are skipped and the skip is printed; they are never reported as passing. No Docker is required. The fixture is a purpose-built fake (`test/helpers/fakeImap.ts`), not a production IMAP server: results show behavior against that fixture, not a provider compatibility matrix.

## Documentation

- `docs/DESIGN_V0.md`: binding v0 design contract
- `docs/THREAT_MODEL.md`: what is protected, from whom, and what is not
- `docs/OPERATIONS.md`: deployment, keys, backup and restore, revocation, troubleshooting
- `docs/CLIENTS.md`: which clients are tested, registration modes, token lifetimes
- `docs/PRD.md`, `docs/VERSION_PLAN.md`: requirements and release plan

## Credits and license

MIT, see `LICENSE`. The v0 baseline was imported from [mkrasselt1/imap-mcp-server](https://github.com/mkrasselt1/imap-mcp-server) (MIT, as declared in its README); large parts have since been replaced (storage, authorization model, encryption, tools). Thanks to its author for the starting point.
