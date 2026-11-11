# Migration: Express + server-rendered HTML to Nuxt 4 SPA + Nitro/h3

Status: in progress. This file is the shared contract for the parallel workstreams. Change it only together with the code.

## Goals

- One deployable: a Nuxt 4 app (`ssr: false`) built with the Nitro `node-server` preset. Nitro/h3 replaces Express; the SPA replaces the HTML views.
- UI built with shadcn-vue (Tailwind v4, reka-ui) in `app/components/ui`.
- **No behaviour change on the machine-facing protocol**: `/mcp`, `/oauth/token`, `/oauth/register`, `/oauth/revoke`, `/.well-known/*`, `/healthz`, `/readyz` keep paths, status codes, headers and bodies. The existing integration tests for these must keep passing unchanged.
- Security properties preserved (see "Security" below). Fail closed everywhere it does today.

## Layout

```
nuxt.config.ts
app/                         SPA (Nuxt 4 srcDir)
  app.vue  pages/  layouts/  middleware/  composables/  components/  components/ui/ (shadcn-vue)  assets/css/
shared/                      types shared by app and server (Nuxt 4 `shared/` dir)
  types/api.ts               every DTO below
server/
  api/                       admin JSON API (cookie session + CSRF header)       -> /api/*
  routes/                    protocol endpoints at the site root                  -> /mcp, /oauth/*, /.well-known/*, /healthz, /readyz
  middleware/                request id, security headers, CORS (protocol paths only)
  plugins/boot.ts            db open + migrate, sidecar start, audit pruner, graceful shutdown (Nitro `close` hook + SIGTERM/SIGINT)
  utils/                     h3 helpers (auto-imported): session, csrf, requireAdmin, rateLimit, bearerAuth, readJson/validation, apiError
  core/                      domain code moved unchanged from src/ (db, imap, sidecar, mcp, policy, audit, oauth/common, log, config, types)
drizzle/                     SQL migrations (unchanged)
sidecar/                     Go sidecar (unchanged)
test/                        vitest (unit + integration), helpers talk to the JSON API
```

`src/` is deleted at the end of the migration. Domain modules move to `server/core/` with `git mv` and import-path fixes only; their logic is not rewritten here. Express types (`Request`, `Response`) must not appear in `server/core`.

## Runtime rules

- Nitro 2 / h3 v1 (what Nuxt 4 ships). Handlers get `event`; use `event.node.req/res` only where a Node-native API demands it (the MCP SDK transport).
- Config is read from `process.env` lazily, exactly as `src/config.ts` does today (not baked at build time). Do not use `runtimeConfig` for secrets.
- Native modules (`better-sqlite3`) are externalised and traced into `.output/`. Migrations (`drizzle/`) and the sidecar binary are resolved relative to `process.cwd()` / `SIDECAR_BIN`, as today; the Dockerfile copies them next to `.output/`.
- The SPA is served by Nitro from `.output/public` with `index.html` fallback for any GET that is not under `/api`, `/oauth/{token,register,revoke}`, `/.well-known`, `/mcp`, `/healthz`, `/readyz`. Note `GET /oauth/authorize` is a SPA route (consent page).

## Admin JSON API (all under `/api`)

Conventions
- JSON in and out. Success: 200 with a body, or 204 without. Errors: `{ "error": { "code": string, "message": string } }` with 400 (validation), 401 (not signed in), 403 (CSRF / forbidden), 404, 409, 429, 500. Messages are the human strings the old UI showed.
- Cookie `imap2mcp.sid` (sealed h3 session, `httpOnly`, `sameSite=lax`, `secure` iff `BASE_URL` is https, 24 h). Server-side state is only inside the sealed cookie: `{ admin?: true, csrf?: string, returnTo?: string }`.
- Every non-GET/HEAD request under `/api` must send `X-CSRF-Token: <session.csrf>` and `Content-Type: application/json`; otherwise 403 `csrf`. The token comes from `GET /api/session`.
- All routes except `session`, `setup`, `login` require an admin session (401 otherwise). `setup` and `login` are rate limited as today.
- Types of every DTO live in `shared/types/api.ts`.

| Method + path | Request body / query | Response |
|---|---|---|
| `GET /api/session` | | `{ setupRequired, authenticated, csrfToken, registrationMode: "dynamic"\|"admin", baseUrl }` |
| `POST /api/setup` | `{ token, password, password2 }` | 204, signs in. 404 once an admin exists. 403 wrong token. 400 password rules |
| `POST /api/login` | `{ password }` | 204. 401 wrong password |
| `POST /api/logout` | | 204 |
| `GET /api/overview` | | `{ registrationMode, mailboxes: MailboxSummary[], clients: ClientSummary[], grants: {clientId, mailboxId, capability}[], tokens: TokenSummary[] }` |
| `POST /api/mailboxes` | `{ label, host, port, username, password }` | `Mailbox` (201) |
| `GET /api/mailboxes/:id` | | `MailboxDetail` (mailbox, status, clients that can reach it) |
| `PATCH /api/mailboxes/:id` | `{ label, host, port, username, password? }` | `Mailbox`. A non-empty password resets the status latches |
| `POST /api/mailboxes/:id/test` | | `{ ok, message, folders: string[] }` |
| `POST /api/mailboxes/:id/retry` | | 204 |
| `PUT /api/mailboxes/:id/drafts` | `{ folder }` | 204. 400 if the folder does not exist on the server |
| `DELETE /api/mailboxes/:id` | `{ confirmLabel }` (must equal the label) | 204 |
| `POST /api/clients` | `{ name, redirectUris: string[] }` | `ClientSummary` (403 unless `REGISTRATION_MODE=admin`) |
| `GET /api/clients/:id` | | `ClientDetail` (client, mailboxes with per-capability state, rules, redirect URIs, capability help) |
| `PUT /api/clients/:id/grants` | `{ grants: {mailboxId, capability}[] }` = the complete desired preset set | 204 |
| `POST /api/clients/:id/rules` | `{ mailboxId, folder, operation, effect }` | `Rule` (201) |
| `DELETE /api/clients/:id/rules/:ruleId` | | 204 |
| `POST /api/clients/:id/disable` / `enable` / `revoke` | | 204. `disable` and `revoke` also revoke all tokens. `revoke` also removes all rules |
| `POST /api/tokens/:id/revoke` | | 204 |
| `GET /api/audit` | `client, mailbox, tool, outcome, from, to, page` | `{ events: AuditEvent[], total, page, pages, pageSize, options: { clients, mailboxes, tools, outcomes } }` |
| `GET /api/audit/export.jsonl` / `export.csv` | same filters | file download (cookie-authed GET, streamed) |
| `GET /api/oauth/authorize` | the OAuth authorization request query | `AuthorizeRequest` or a 400 `{error}` for the "page" errors; protocol errors that the old code returned as redirects come back as `{ redirectTo }` |
| `POST /api/oauth/authorize` | OAuth params + `{ decision: "approve"\|"deny", grants: {mailboxId, capability}[] }` | `{ redirectTo }` (the client's `redirect_uri` with `code`/`error`, `state`, `iss`) |

Behaviour for every mutation is exactly what `src/web/routes.ts`, `src/oauth/authorize.ts`, `src/audit/routes.ts` and `src/auth/routes.ts` do today (validation, limits, transactions, status resets). Those files are the specification until `src/` is removed.

## SPA routes

`/setup`, `/login`, `/` (redirects to `/dashboard`), `/dashboard`, `/mailboxes`, `/mailboxes/new`, `/mailboxes/:id`, `/clients`, `/clients/:id`, `/tokens`, `/audit`, `/oauth/authorize`. A global route middleware calls `GET /api/session` once and redirects: setup needed to `/setup`, signed out to `/login?returnTo=...`, signed in on `/login` or `/setup` to `/dashboard`. After sign-in go to `returnTo` when it is a same-site path. Confirmations that were separate pages (disable client, revoke token, delete mailbox) become dialogs.

## Security (must hold after the migration)

- Session secret >= 32 chars, `ENCRYPTION_KEY(_FILE)` rules, fail-closed startup (`FATAL:` and non-zero exit) are unchanged.
- CSRF as above. No CORS with credentials; CORS only on `/mcp`, `/oauth/token`, `/oauth/register`, `/oauth/revoke`, `/.well-known/*`.
- Headers on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` for HTML and API (hashed `/_nuxt/*` assets may be cacheable), HSTS when https. CSP for the SPA: `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'`. The SPA's inline bootstrap script must be covered by a hash or removed, never by `'unsafe-inline'` in `script-src`. Protocol/JSON endpoints keep `default-src 'none'`.
- No `form-action` directive (it breaks the OAuth redirect after approval).
- Secrets stay redacted in logs; the bootstrap token is still printed on first run.
- Rate limits unchanged: setup/login limiters, `/oauth/token` 60/min, health 120/min.

## Workstreams (disjoint file ownership)

| Id | Owns | Does |
|---|---|---|
| P0 | `nuxt.config.ts`, `package.json`, `tsconfig*`, `shared/`, `server/core/` (move), `app/components/ui/`, this file | Foundation, contract, shadcn components installed |
| A | `server/utils/{session,csrf,requireAdmin,rateLimit,apiError,validate}.ts`, `server/middleware/**`, `server/api/{session,setup,login,logout}*` | Auth, CSRF, headers/CSP (incl. SPA inline-script CSP), rate limits |
| B | `server/routes/**`, `server/utils/bearer.ts`, `server/plugins/boot.ts` | MCP + OAuth protocol endpoints, health, lifecycle/shutdown |
| C | `server/api/{overview,mailboxes,clients,tokens,audit,oauth}/**` | Admin JSON API |
| D | `app/{app.vue,layouts,middleware,composables,assets}`, `app/pages/{index,setup,login,dashboard}*`, `app/pages/mailboxes/**`, `app/components/*` (non-ui) used by those | Shell, auth pages, dashboard, mailboxes |
| E | `app/pages/{clients,audit}/**`, `app/pages/oauth/**`, its components | Clients/grants/rules, audit, consent |
| F | `Dockerfile`, `.dockerignore`, `.github/**`, `scripts/**`, `docs/*.md` (except this file), `README.md`, `deploy/**` | Build, image, CI, smoke, docs |
| G | `test/**`, `vitest.config.ts` | Port helpers to the JSON API, keep protocol tests green, add API and UI tests |
