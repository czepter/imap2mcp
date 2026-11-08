<img src="assets/icon.svg" width="64" height="64" alt="">

# imap2mcp

A single-owner bridge that lets AI agents use your IMAP mailboxes through the [Model Context Protocol](https://modelcontextprotocol.io/) (Streamable HTTP), with OAuth 2.1 authorization, encrypted mailbox credentials, and permissions you edit per client and per mailbox.

**Status: Version 1 ("Precision and performance").** v0 gave coarse mailbox-level grants; v1 adds folder x operation rules with explicit deny, and serves reads from a small Go sidecar that keeps a header cache so mailboxes with 10,000 messages stay responsive. See `docs/VERSION_PLAN.md` for what each version promises, `docs/PRD.md` for the requirements, `docs/DESIGN_V0.md` and `docs/DESIGN_V1.md` for the binding design contracts, and `docs/BENCHMARKS.md` for measured numbers (including any gate that failed).

## What it does

- **MCP over Streamable HTTP** at `${BASE_URL}/mcp`, stateless, bearer-token protected.
- **OAuth 2.1 authorization server**: authorization code with mandatory PKCE (S256), RFC 8414/9728 metadata, RFC 7591 dynamic client registration (or admin-created clients), RFC 8707 resource binding to `${BASE_URL}/mcp`, refresh-token rotation. HTTP Basic auth and static API tokens are not accepted anywhere on `/mcp`.
- **Folder x operation policy** (v1). The owner edits, per OAuth client and mailbox, a list of rules `(folder, operation, allow|deny)`:

  | Operation | Needs OAuth scope | Tools |
  |---|---|---|
  | `search`, `read_headers`, `read_body` | `mail:read` | `list_folders`, `search_messages`, `read_message` |
  | `draft` | `mail:draft` | `create_draft` (Drafts folder only) |
  | `move`, `flag` | `mail:organize` | `move_message` (needs `move` on source **and** destination folder), `set_flags` |

  A folder selector is an exact IMAP path, `*` (everything) or `prefix/*` (the prefix and its sub-folders); case-sensitive, nothing else is a wildcard. **Any matching deny wins; otherwise any matching allow; otherwise deny.** The token's scopes stay a ceiling. Rules are read on every call, so removing a rule or revoking a client applies to the next call (existing tokens included), and writes are re-checked right before they are sent. Search never touches, counts or reveals folders where `search` is denied, and error messages do not reveal whether a denied folder exists. The v0 "presets" (read / draft / organize per mailbox) remain as shortcuts that expand to rules; upgrading from v0 migrates grants without widening anyone's access.
- **Go sidecar for reads** (v1). LIST/STATUS/FETCH/SEARCH run in `sidecar/` (Go, go-imap v2), reached over a private Unix socket (`DATA_DIR/sidecar.sock`, mode 0600) with a per-process secret passed on the child's stdin. Node stays the policy authority and authorizes before and filters after every sidecar call. The sidecar caches UIDs, flags and envelopes in memory (never bodies), keyed by mailbox, folder, UIDVALIDITY and UID; UIDNEXT drives fetching new mail, and a periodic UID/flag reconciliation (`SYNC_RECONCILE_SECS`, default 30) catches expunges and flag changes made by other clients. Writes (APPEND, MOVE, STORE) stay in Node. If the sidecar is down, tools return `UPSTREAM_ERROR` while Node restarts it; the cache is rebuilt from IMAP.
- **Mailbox secrets encrypted at rest** (AES-256-GCM, per-record IV, ciphertext bound to its table/row/column). The master key lives in a file outside the database. A missing or malformed key stops the server from starting; a wrong key makes every mailbox operation fail.
- **Safe IMAP behavior**: TLS only with certificate validation, no plaintext fallback; reads use `BODY.PEEK` so unread state is not changed; moves use `UID MOVE` or `UID COPY` plus flag and `UID EXPUNGE` of that UID only (never a plain `EXPUNGE`); `\Deleted` cannot be set through the tools.
- **SSRF policy**: a mailbox host must resolve to public addresses unless it is listed in `ALLOW_PRIVATE_HOSTS`.

## What it does not do

No sending (no SMTP at all), no permanent deletion, no persistent audit log (v2), no multi-user tenancy (v3), no key rotation tooling yet. Not in v1 either: IMAP XOAUTH2 and CONDSTORE/QRESYNC (see `docs/BACKLOG.md`). Mail content is untrusted input: anything a client with `read` can read is exposed to that client and its model. See `docs/THREAT_MODEL.md`.

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
3. Point your MCP client at `${BASE_URL}/mcp`. It discovers OAuth, registers, and sends you to the consent screen, where you choose which mailbox access to allow. Afterwards refine the rules per folder and operation under **Clients**, revoke a client or its tokens, all with effect on the next call.

The Docker image builds the Go sidecar in a separate stage and includes it at `sidecar/bin/sidecar`.

Run it behind an HTTPS reverse proxy (the compose file binds `127.0.0.1:3000`). With an `https://` `BASE_URL` the session cookie is `Secure` and one proxy hop is trusted. See `docs/OPERATIONS.md` for backup, key handling and upgrades.

### Without Docker

```bash
npm ci
npm run build:sidecar        # needs Docker (golang:1.23-alpine) or a local Go toolchain; writes sidecar/bin/sidecar
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
| `SIDECAR_BIN` | no | Path of the sidecar binary. Default `sidecar/bin/sidecar`. |
| `SIDECAR_DISABLED` | no | `1` uses the v0 direct IMAP read path. Debugging only; bypasses the sidecar and its cache. |
| `SYNC_RECONCILE_SECS` | no | Interval of the sidecar's UID/flag reconciliation. Default 30. |
| `SIDECAR_EXTRA_CA_FILE` | no | Extra CA bundle the sidecar trusts for IMAP TLS (self-hosted mail servers, tests). |

## Tests

```bash
npm test                  # everything
npm run test:unit
npm run test:integration  # spawns the real server against an in-process IMAP-over-TLS fixture
npm run test:v1           # only the v1 end-to-end suites (policy matrix, sidecar boundary, sync correctness)
npm run bench             # v1 performance gate: 10,000 messages, 20 ms RTT, sidecar in Docker --cpus=2 --memory=2g
```

The integration suite needs `openssl` (to create a self-signed certificate for the fixture, injected through `NODE_EXTRA_CA_CERTS` so certificate validation stays on). If it is missing, those tests are skipped and the skip is printed; they are never reported as passing. The `v1-*` suites additionally need the built sidecar (`npm run build:sidecar`) and are skipped, with a printed reason, without it. Docker is needed only to build the sidecar without a local Go toolchain and for `npm run bench`. The fixture is a purpose-built fake (`test/helpers/fakeImap.ts`), not a production IMAP server: results show behavior against that fixture, not a provider compatibility matrix.

## Documentation

- `docs/DESIGN_V0.md`: binding v0 design contract
- `docs/DESIGN_V1.md`: binding v1 design contract (policy rules, sidecar RPC, performance gate)
- `docs/BENCHMARKS.md`: v1 gate results with machine info; failed gates are reported as failed
- `docs/BACKLOG.md`: deferred work (XOAUTH2, CONDSTORE/QRESYNC) and why
- `docs/THREAT_MODEL.md`: what is protected, from whom, and what is not
- `docs/OPERATIONS.md`: deployment, keys, backup and restore, revocation, troubleshooting
- `docs/CLIENTS.md`: which clients are tested, registration modes, token lifetimes
- `docs/PRD.md`, `docs/VERSION_PLAN.md`: requirements and release plan

## Credits and license

MIT, see `LICENSE`. The v0 baseline was imported from [mkrasselt1/imap-mcp-server](https://github.com/mkrasselt1/imap-mcp-server) (MIT); large parts have since been replaced (storage, authorization model, encryption, tools). Thanks to its author for the starting point.
