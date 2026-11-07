# MCP clients, registration and token lifetimes

This page states only what the test suite verifies. Everything else is listed as untested.

## Verified

Tested end to end against the real server process (`test/integration/oauth-transport.test.ts`) with the **official MCP TypeScript SDK client** (`@modelcontextprotocol/sdk` 1.29.0, `StreamableHTTPClientTransport` plus its built-in OAuth client flow):

1. Unauthenticated `POST /mcp` -> `401` with `WWW-Authenticate: Bearer ... resource_metadata=...`.
2. Discovery of protected-resource and authorization-server metadata.
3. Dynamic client registration (RFC 7591).
4. Authorization code + PKCE S256 with the `resource` parameter, owner consent in the browser UI, code exchange.
5. Tool calls over Streamable HTTP with the issued bearer token.

## Not verified

Claude.ai / Claude Desktop / Claude Code, ChatGPT, Cursor, VS Code, MCP Inspector, and other hosted or desktop clients have **not** been tested against this server. They should work if they implement the MCP authorization spec (metadata discovery, PKCE S256, public client, bearer tokens), but that is an expectation, not a tested statement. Report incompatibilities with the client name and version.

## What a client must support

- Streamable HTTP transport at `${BASE_URL}/mcp` (`POST`; the server is stateless and does not issue `Mcp-Session-Id`).
- OAuth 2.1 as a **public client**: `token_endpoint_auth_method=none`, no client secret. Authorization on the token endpoint via `Authorization` header (Basic or Bearer) is refused.
- PKCE with `code_challenge_method=S256`. `plain` and missing challenges are rejected.
- Redirect URIs must be `https://...` or `http://localhost|127.0.0.1...`, without fragment, and must match the registered value exactly.
- `resource`, if sent, must equal `${BASE_URL}/mcp` (RFC 8707); if omitted it defaults to that value.
- Scopes: `mail:read`, `mail:draft`, `mail:organize`. If none is requested, all three are requested. The consent screen shows only the requested scopes; the token carries only the scopes for which the owner ticked at least one mailbox.
- Static tokens, API keys, HTTP Basic auth and cookies cannot authorize `/mcp`.

## Registration modes (`REGISTRATION_MODE`)

| Mode | Behavior | Verified |
|---|---|---|
| `dynamic` (default) | `POST /oauth/register` creates a client record with **no grants**; it can reach nothing until the owner consents and ticks mailboxes. Invalid redirect URIs (`http://` non-loopback, `javascript:`, fragments, garbage) are rejected with 400. | yes |
| `admin` | `POST /oauth/register` returns 403. The owner creates clients in the UI (**Dashboard -> Add client**) and gives the `client_id` to the client. | yes |

Dynamic registration is unauthenticated by nature (RFC 7591). The record is inert, but it is storage on your server; use `admin` mode if the endpoint is publicly reachable and you want to avoid that.

## Token lifetimes

| Token | Lifetime | Notes (verified) |
|---|---|---|
| Authorization code | 10 minutes | Single use; second use is refused. |
| Access token | 1 hour (`expires_in: 3600`) | Opaque, 43 base64url characters; only its SHA-256 is stored. Expired, revoked or wrong-audience tokens get 401. |
| Refresh token | 30 days | Rotated on every use; the previous access token stops working at rotation. Presenting an already-used refresh token is refused and revokes the lineage, so a client that retries a lost refresh response must re-authorize. A refresh cannot request a scope that was not consented. |

Grants (what a client may do) are separate from token lifetime: grant changes in the UI apply to the next tool call of any live token. A grant added after consent never widens an existing token; the client must authorize again to obtain the extra scope.

## Tools

`list_mailboxes`, `list_folders`, `search_messages`, `read_message`, `create_draft`, `move_message`, `set_flags`. Message references are objects `{mailbox, folder, uidValidity, uid}`; limits: 50 per page, 25 per batch, 200 KB body. Errors are `{code, message}` with `FORBIDDEN`, `NOT_FOUND`, `STALE_REFERENCE`, `INVALID_INPUT`, `UNSUPPORTED`, `UPSTREAM_ERROR`, `UNKNOWN_OUTCOME`.
