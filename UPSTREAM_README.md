# IMAP MCP Server

[![Docker Hub](https://img.shields.io/docker/v/mkrasselt1/imap-mcp-server?label=Docker%20Hub)](https://hub.docker.com/r/mkrasselt1/imap-mcp-server)

A multi-agent, multi-user HTTP IMAP bridge that acts as a remote [MCP](https://modelcontextprotocol.io/) server with built-in OAuth 2.1 authorization. Designed to let AI agents (like Claude.ai) securely access email on behalf of users, with granular per-agent permission control.

## Features

- **MCP over Streamable HTTP** — standard protocol that Claude.ai and other MCP clients speak natively
- **OAuth 2.1 Authorization Server** — RFC 8414 discovery, RFC 7591 Dynamic Client Registration, PKCE-enforced flows
- **Multi-user / multi-agent** — each user manages their own IMAP accounts; each agent connection gets its own scoped token
- **Granular permissions** — users choose exactly which capabilities to grant each agent:
  | Scope | Grants |
  |-------|--------|
  | `mail:folders` | List mailbox folders |
  | `mail:read` | Read email messages |
  | `mail:search` | Search emails |
  | `mail:modify` | Move, flag, delete messages |
  | `mail:send` | Send emails via SMTP |
- **Encrypted credential storage** — IMAP/SMTP passwords encrypted with AES-256-GCM at rest
- **Connection pooling** — IMAP connections are reused across tool calls with auto-disconnect on idle
- **Web dashboard** — manage email accounts and revoke agent tokens

## Quick Start with Docker

> **Important:** The `-v` volume mount is required to persist your database (users, accounts, tokens) across container updates. Without it, all data is lost when the container is recreated.

```bash
docker run -d \
  --name imap-bridge \
  -p 3000:3000 \
  -v imap-bridge-data:/app/data \
  -e BASE_URL=https://your-domain.com \
  -e ENCRYPTION_KEY=$(openssl rand -hex 32) \
  -e SESSION_SECRET=$(openssl rand -hex 32) \
  mkrasselt1/imap-mcp-server
```

> **Tip:** Save your `ENCRYPTION_KEY` — if it changes, stored IMAP passwords become unrecoverable. Write it to an `.env` file or use Docker secrets.

Or with Docker Compose:

```bash
git clone https://github.com/mkrasselt1/imap-mcp-server.git
cd imap-mcp-server
cp .env.example .env
# Edit .env with your values
docker compose up -d
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `BASE_URL` | Yes | Public URL of the server (e.g. `https://mail.example.com`). Must be HTTPS for Claude.ai. |
| `PORT` | No | Listen port (default: `3000`) |
| `ENCRYPTION_KEY` | Yes | 64-char hex string for AES-256-GCM encryption. Generate with `openssl rand -hex 32` |
| `SESSION_SECRET` | Yes | Random string for session cookies. Generate with `openssl rand -hex 32` |

## Setup

### 1. Deploy the server

Deploy behind a reverse proxy (nginx, Caddy, Traefik) with TLS. Claude.ai requires HTTPS.

### 2. Create an account and add email credentials

1. Visit `https://your-domain.com/signup` and create an account
2. Go to the Dashboard and click **Add Email Account**
3. Enter your IMAP server details and credentials (use an App Password for Gmail/Outlook)
4. Optionally add SMTP settings for sending

### 3. Connect from Claude.ai

1. Go to [Claude.ai Settings > Integrations](https://claude.ai/settings/integrations)
2. Click **Add Custom Connector** (or **Add MCP Server**)
3. Enter your server URL: `https://your-domain.com/mcp`
4. Claude.ai will automatically:
   - Discover OAuth endpoints via `/.well-known/oauth-authorization-server`
   - Register itself as an OAuth client (Dynamic Client Registration)
   - Redirect you to the consent screen
5. On the consent screen, select which email account and permissions to grant
6. After authorizing, Claude.ai can use the email tools

## OAuth 2.1 Flow

```
Claude.ai                          IMAP Bridge                    User
   │                                    │                           │
   │  GET /.well-known/oauth-           │                           │
   │  authorization-server              │                           │
   │───────────────────────────────────>│                           │
   │  { endpoints, scopes }            │                           │
   │<───────────────────────────────────│                           │
   │                                    │                           │
   │  POST /oauth/register             │                           │
   │  { redirect_uris }                │                           │
   │───────────────────────────────────>│                           │
   │  { client_id }                    │                           │
   │<───────────────────────────────────│                           │
   │                                    │                           │
   │  Redirect to /oauth/authorize      │                           │
   │  + PKCE code_challenge             │                           │
   │───────────────────────────────────>│  Login form               │
   │                                    │──────────────────────────>│
   │                                    │  Username + password      │
   │                                    │<──────────────────────────│
   │                                    │  Consent screen           │
   │                                    │  (select account + perms) │
   │                                    │──────────────────────────>│
   │                                    │  Approve                  │
   │                                    │<──────────────────────────│
   │  Callback with auth code          │                           │
   │<───────────────────────────────────│                           │
   │                                    │                           │
   │  POST /oauth/token                │                           │
   │  + code_verifier (PKCE)           │                           │
   │───────────────────────────────────>│                           │
   │  { access_token, refresh_token }  │                           │
   │<───────────────────────────────────│                           │
   │                                    │                           │
   │  POST /mcp (tool calls)           │                           │
   │  Authorization: Bearer <token>    │                           │
   │───────────────────────────────────>│  IMAP                    │
   │  { tool results }                 │                           │
   │<───────────────────────────────────│                           │
```

## MCP Tools

| Tool | Scope Required | Description |
|------|---------------|-------------|
| `list_folders` | `mail:folders` | List all mailbox folders |
| `list_messages` | `mail:read` | List messages with pagination. Supports `includeBody` to fetch message content inline. |
| `read_message` | `mail:read` | Read full message by UID. Supports `uids` array to batch-read up to 10 messages in one call. |
| `search_messages` | `mail:search` | Search by sender, date, subject, body. Supports `includeBody` to fetch message content inline. |
| `move_message` | `mail:modify` | Move message between folders |
| `flag_message` | `mail:modify` | Set read/unread, star, delete flags |
| `send_mail` | `mail:send` | Send email via SMTP |

## Development

```bash
npm install
npm run dev     # starts with tsx watch
```

```bash
npm run build   # compile TypeScript
npm start       # run compiled output
```

## Security Notes

- **HTTPS required** for production — Claude.ai will not connect over plain HTTP
- **App Passwords** — use app-specific passwords for Gmail, Outlook, etc. rather than your main password
- **Encryption key** — keep your `ENCRYPTION_KEY` safe; losing it means stored IMAP passwords become unrecoverable
- **Token revocation** — users can revoke agent tokens from the dashboard at any time
- **PKCE enforced** — all OAuth flows require Proof Key for Code Exchange (S256)
- **Content Security Policy** — restrictive CSP prevents XSS and framing attacks
- **Token refresh** — access tokens expire after 1 hour; MCP clients automatically refresh using the refresh token (30-day lifetime)

## License

MIT
