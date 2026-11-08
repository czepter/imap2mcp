import { escapeHtml } from "./escapeHtml.js";

// The CSP is `default-src 'none'; style-src 'unsafe-inline'`: no scripts and no image
// loads, so everything here is CSS-only (native checkboxes, <details>, inline SVG).
export const baseCss = `
:root{--bg:#f4f5f7;--surface:#fff;--ink:#14181f;--muted:#5b6475;--line:#e1e4ea;--line-strong:#7d8799;--brand:#1f4fd8;--brand-ink:#fff;--danger:#b42318;--danger-soft:#fdecea;--danger-ink:#fff;--ok:#0f6e52;--ok-soft:#e3f5ed;--warn:#8a4f00;--warn-soft:#fff1d6;--focus:#1f4fd8;--side:#10151f;--side-ink:#c3cbdb;--side-on:#1d2535;--side-hover:#171e2c;--side-line:#1d2535;--logo:#7ba0ff}
@media (prefers-color-scheme:dark){:root{--bg:#0d1118;--surface:#161b25;--ink:#e8ecf3;--muted:#9aa4b6;--line:#262d3a;--line-strong:#6b7588;--brand:#7ba0ff;--brand-ink:#0d1118;--danger:#ff8a80;--danger-soft:#3a1a1a;--danger-ink:#14181f;--ok:#4cc9a0;--ok-soft:#12302a;--warn:#f2b45a;--warn-soft:#3a2c12;--focus:#9db8ff;--side:#080b11;--side-ink:#aab4c6;--side-on:#161d2b;--side-hover:#10151f;--side-line:#161d2b}}
*{box-sizing:border-box;margin:0}
body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink);font-variant-numeric:tabular-nums}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:4px}
a{color:var(--brand)}
.app{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
.side{background:var(--side);color:var(--side-ink);padding:20px 12px;display:flex;flex-direction:column;gap:2px}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;padding:2px 10px 20px;font-size:15px;color:inherit}
.side .brand{color:#fff}.brand svg{width:24px;height:24px;flex:none}
.side a{display:block;color:var(--side-ink);text-decoration:none;padding:8px 10px;border-radius:7px}
.side a[aria-current]{background:var(--side-on);color:#fff;font-weight:600}.side a:hover{background:var(--side-hover)}
.side .foot{margin-top:auto;font-size:12px;padding:12px 10px 0;border-top:1px solid var(--side-line)}
main{padding:28px 36px 48px;max-width:1040px;min-width:0}
main.narrow{max-width:700px}
main.center{min-height:100vh;display:grid;place-items:center;padding:24px;max-width:none}
.crumb{color:var(--muted);font-size:12px;margin-bottom:6px}.crumb a{color:var(--muted)}
h1{font-size:22px;font-weight:650;letter-spacing:-.01em;text-wrap:balance}
.head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:22px;gap:16px}.head p{color:var(--muted);margin-top:4px}
h2{font-size:15px;font-weight:650}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;margin-bottom:20px;overflow:hidden}
.card>header{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--line)}
.card .pad{padding:18px}.scroll{overflow-x:auto;background:linear-gradient(to right,var(--surface) 30%,transparent) left,linear-gradient(to left,var(--surface) 30%,transparent) right,radial-gradient(farthest-side at 0 50%,rgb(0 0 0/.18),transparent) left,radial-gradient(farthest-side at 100% 50%,rgb(0 0 0/.18),transparent) right;background-repeat:no-repeat;background-size:36px 100%,36px 100%,12px 100%,12px 100%;background-attachment:local,local,scroll,scroll}
table{width:100%;border-collapse:collapse}
th{font-size:12px;letter-spacing:.02em;color:var(--muted);font-weight:600;text-align:left;padding:9px 18px;background:color-mix(in srgb,var(--bg) 60%,var(--surface));white-space:nowrap}
td,tbody th{padding:11px 18px;border-top:1px solid var(--line);vertical-align:middle}
tbody th{background:var(--surface);color:var(--ink);font-size:14px;white-space:normal}
td.c,th.c{text-align:center}td.r{text-align:right}
td:first-child,th:first-child{position:sticky;left:0}td:first-child{background:var(--surface)}
td>div+div{margin-top:4px}
.sub,.small{color:var(--muted);font-size:13px}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px}
.btn,button{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:34px;padding:6px 14px;border-radius:8px;border:1px solid var(--line-strong);background:var(--surface);color:var(--ink);font:inherit;font-weight:550;cursor:pointer;text-decoration:none;white-space:nowrap}
.btn:hover,button:hover{background:var(--bg)}
.btn.p,button.p{background:var(--brand);border-color:var(--brand);color:var(--brand-ink)}.btn.p:hover,button.p:hover{background:var(--brand);filter:brightness(1.08)}
.btn.d,button.d{color:var(--danger);border-color:var(--danger)}.btn.d:hover,button.d:hover{background:var(--danger-soft)}
.btn.dfill,button.dfill{background:var(--danger);border-color:var(--danger);color:var(--danger-ink)}
.btn.s,button.s{min-height:30px;padding:3px 10px;font-size:13px}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:1px 9px;border-radius:99px;white-space:nowrap}
.pill.ok{background:var(--ok-soft);color:var(--ok)}.pill.off{background:var(--danger-soft);color:var(--danger)}.pill.warn{background:var(--warn-soft);color:var(--warn)}
.pill.read{background:var(--bg);color:var(--ink);box-shadow:inset 0 0 0 1px var(--line-strong)}
.pill.draft,.pill.organize{background:var(--warn-soft);color:var(--warn)}.pill.organize{box-shadow:inset 0 0 0 1px var(--warn)}
.none{color:var(--muted)}
.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:0 14px;align-items:end}.filters .row{padding-bottom:2px}
.pager{display:flex;gap:10px;align-items:center;justify-content:space-between;padding:12px 18px;border-top:1px solid var(--line)}
label{display:block;font-weight:600;margin:14px 0 5px;font-size:13px}
input[type=text],input[type=password],input[type=number],input[type=date],select,textarea{width:100%;padding:8px 12px;min-height:36px;border:1px solid var(--line-strong);border-radius:8px;font:inherit;background:var(--surface);color:var(--ink)}
.hint{color:var(--muted);font-size:13px;margin-top:5px}.grid2{display:grid;grid-template-columns:1fr 140px;gap:14px}
.alert,.error,.success{padding:10px 14px;border-radius:9px;margin-bottom:18px;display:flex;gap:10px;justify-content:space-between;align-items:center}
.success{background:var(--ok-soft);color:var(--ok)}.error{background:var(--danger-soft);color:var(--danger)}.alert.warn{background:var(--warn-soft);color:var(--warn)}.alert a{color:inherit;font-weight:600}
input[type=checkbox]{width:22px;height:22px;margin:0;accent-color:var(--brand);cursor:pointer;vertical-align:middle}
input[type=checkbox]:disabled{opacity:.45;cursor:not-allowed}
.panel{width:100%;max-width:440px;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:30px}
.panel.wide{max-width:560px}.panel .brand{color:var(--ink);padding:0 0 18px}
.row{display:flex;gap:10px;align-items:center}.grow{flex:1}
.danger-zone{border-color:var(--danger)}.danger-zone>header{background:var(--danger-soft);color:var(--danger)}
.confirm{display:flex;gap:12px;align-items:center;justify-content:space-between;background:var(--warn-soft);padding:12px 18px;border-top:1px solid var(--line)}
form.inline{display:inline}
@media (max-width:820px){.app{grid-template-columns:1fr;grid-template-rows:auto 1fr}.side{flex-direction:row;flex-wrap:wrap;align-items:center;align-content:flex-start;padding:10px 12px}.brand{padding:0 12px 0 4px}.side .foot{margin:0 0 0 auto;border:0;padding:0}main{padding:20px 16px 40px}.grid2{grid-template-columns:1fr}.head{flex-direction:column}}
`;

export const logo = (fill = "var(--logo)", stroke = "var(--side)") =>
  `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 9.2-8 11-4.6-1.8-8-6-8-11V5z" fill="${fill}"/><path d="M7.5 10.5l4.5 3 4.5-3M7.5 10.5h9v5h-9z" fill="none" stroke="${stroke}" stroke-width="1.4" stroke-linejoin="round"/></svg>`;

export type NavKey = "overview" | "mailboxes" | "clients" | "tokens" | "audit";
const NAV: Array<[NavKey, string, string]> = [
  ["overview", "Overview", "/dashboard"],
  ["mailboxes", "Mailboxes", "/dashboard#mailboxes"],
  ["clients", "Clients", "/dashboard#clients"],
  ["tokens", "Tokens", "/dashboard#tokens"],
  ["audit", "Audit log", "/audit"],
];

/** A titled card. `title` and `aside` are trusted HTML built by the caller (escape dynamic parts). */
export function card(id: string, title: string, body: string, opts: { aside?: string; cls?: string; padded?: boolean } = {}): string {
  return `<section class="card${opts.cls ? ` ${opts.cls}` : ""}" id="${id}" aria-labelledby="${id}-h"><header><h2 id="${id}-h">${title}</h2>${opts.aside ?? ""}</header>${opts.padded ? `<div class="pad">${body}</div>` : body}</section>`;
}

/** Document shell. With `username` the admin sidebar is shown (`active` marks the section). */
export function shell(title: string, inner: string, head = ""): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} - IMAP Bridge</title>
<style>${baseCss}</style>${head}
</head><body>${inner}</body></html>`;
}

export function layout(title: string, body: string, username?: string, active?: NavKey): string {
  if (!username) return shell(title, `<main class="center">${body}</main>`);
  const links = NAV.map(([k, label, href]) => `<a href="${href}"${k === active ? ' aria-current="page"' : ""}>${label}</a>`).join("");
  return shell(title, `<div class="app"><aside class="side"><div class="brand">${logo()}IMAP Bridge</div>
<nav aria-label="Main" style="display:contents">${links}</nav>
<div class="foot">Signed in as ${escapeHtml(username)}<br><a href="/logout" style="padding:4px 0">Log out</a></div></aside>
<main>${body}</main></div>`);
}
