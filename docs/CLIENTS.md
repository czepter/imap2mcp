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

| Tool | Arguments |
|---|---|
| `list_mailboxes` | none |
| `list_folders` | `mailbox` |
| `search_messages` | `mailbox`, `folder`; optional `text`, `from`, `to`, `subject`, `since`, `before` (`YYYY-MM-DD`), `unseen`, `flagged`, `limit` (1-50), `cursor` |
| `read_message` | `ref`; optional `include` (`["headers"]`, `["body"]` or both) |
| `create_draft` | `mailbox`, `subject`, `body`; optional `to[]`, `cc[]`, `inReplyTo` |
| `move_message` | `ref`, `destination` |
| `set_flags` | `refs[]` (1-25), optional `add[]`, `remove[]` |

`mailbox` is the id from `list_mailboxes`. `ref` is `{mailbox, folder, uidValidity, uid}` as returned by earlier calls. Limits: 50 per page, 25 per batch, 200 KB body. Errors are `{code, message, requestId, retryable, operatorAction?}`; see `docs/ERRORS.md` for all codes.

## Trying it with curl

A hand-driven OAuth 2.1 + PKCE round trip, useful to check a deployment without any MCP client. Run it from the host against the published port; `BASE_URL` must be what is configured (only the `resource` value has to match it exactly). Needs `curl`, `openssl` and `jq`. The browser step needs an admin login and at least one mailbox.

```bash
B=http://127.0.0.1:3000                 # where you can reach the bridge
BASE_URL=https://mcp.example.com        # exactly the configured BASE_URL (no trailing slash)
REDIR=http://127.0.0.1:8976/cb          # nothing needs to listen there; you copy the code from the address bar

# 1. Register (REGISTRATION_MODE=dynamic; in admin mode create the client in the UI and use its client_id)
CID=$(curl -s -X POST $B/oauth/register -H 'content-type: application/json' \
  -d "{\"client_name\":\"curl-demo\",\"redirect_uris\":[\"$REDIR\"],\"token_endpoint_auth_method\":\"none\"}" | jq -r .client_id)

# 2. PKCE pair
VER=$(openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-64)
CH=$(printf %s "$VER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# 3. Authorize in a browser: open this URL, log in, tick the mailbox capabilities, press "Allow".
#    The browser is sent to $REDIR?code=...&state=xyz and shows a connection error: that is fine; copy the code.
echo "$B/oauth/authorize?response_type=code&client_id=$CID&redirect_uri=$(jq -rn --arg u "$REDIR" '$u|@uri')&code_challenge=$CH&code_challenge_method=S256&state=xyz&scope=mail%3Aread&resource=$(jq -rn --arg u "$BASE_URL/mcp" '$u|@uri')"

# 4. Exchange the code (valid 10 minutes, single use)
CODE=<paste code>
curl -s -X POST $B/oauth/token -d grant_type=authorization_code -d code=$CODE -d client_id=$CID \
  --data-urlencode redirect_uri=$REDIR -d code_verifier=$VER --data-urlencode resource=$BASE_URL/mcp | tee token.json
AT=$(jq -r .access_token token.json)

# 5. Call the MCP endpoint (both Accept types are required; the reply is an SSE frame)
curl -s -X POST $B/mcp -H "authorization: Bearer $AT" -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
curl -s -X POST $B/mcp -H "authorization: Bearer $AT" -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_mailboxes","arguments":{}}}'
```

Every step was run against a live container, including step 3 emulated with a cookie-jar login and the consent form POST (the real browser rendering was not exercised). Observed: registration returns a `client_id`; an unauthenticated `/oauth/authorize` redirects to `/login`; the token reply contains `access_token`, `refresh_token`, `expires_in: 3600` and the consented scope; `tools/list` returns the seven tools; `tools/call list_mailboxes` returns the granted mailbox. Without a token, `/mcp` answers 401.
