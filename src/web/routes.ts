import { Router } from "express";
import type { Request, Response } from "express";
import { randomUUID } from "crypto";
import { getDb } from "../db/database.js";
import { config } from "../config.js";
import { requireAdmin, csrfProtection, csrfToken, CSRF_FIELD } from "./deps.js";
import {
  listMailboxes, getMailbox, createMailbox, updateMailbox, deleteMailbox, setDraftsFolder, testMailbox, validateMailboxInput,
} from "../imap/mailboxes.js";
import { layout } from "./views/layout.js";
import { escapeHtml as esc } from "./views/escapeHtml.js";
import { CAPABILITIES, validRedirectUri } from "../oauth/common.js";
import type { Capability } from "../types.js";

const router = Router();

// Everything below is admin-only and CSRF-protected on state changes. Path-scoped so
// /mcp, /oauth/*, /login, /setup are untouched.
const PREFIXES = ["/dashboard", "/mailboxes", "/clients", "/tokens"];
router.use(PREFIXES, requireAdmin, csrfProtection);

const csrf = (req: Request) => `<input type="hidden" name="${CSRF_FIELD}" value="${esc(csrfToken(req))}">`;
const post = (req: Request, action: string, label: string, cls = "", confirm = "") =>
  `<form method="POST" action="${esc(action)}" class="inline"${confirm ? `` : ""}>${csrf(req)}<button type="submit" class="${cls}">${esc(label)}</button></form>`;
const flash = (req: Request) => {
  const m = typeof req.query.msg === "string" ? req.query.msg : "";
  const e = typeof req.query.err === "string" ? req.query.err : "";
  return (e ? `<div class="error">${esc(e)}</div>` : "") + (m ? `<div class="success">${esc(m)}</div>` : "");
};
const back = (res: Response, path: string, kind: "msg" | "err", text: string) =>
  res.redirect(`${path}${path.includes("?") ? "&" : "?"}${kind}=${encodeURIComponent(text)}`);
const str = (v: unknown, max = 500) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const send = (res: Response, title: string, body: string) => res.send(layout(title, body, "admin"));

// ---------------- Dashboard ----------------
router.get("/dashboard", (req, res) => {
  const db = getDb();
  const mailboxes = listMailboxes();
  const clients = db.prepare("SELECT client_id, client_name, created_at, disabled FROM oauth_clients ORDER BY created_at DESC").all() as any[];
  const tokens = db.prepare(
    `SELECT t.id, t.client_id, t.scopes, t.expires_at, t.refresh_expires_at, t.created_at, c.client_name
       FROM oauth_tokens t JOIN oauth_clients c ON c.client_id = t.client_id
      WHERE t.revoked = 0 AND (t.expires_at > ? OR (t.refresh_expires_at IS NOT NULL AND t.refresh_expires_at > ?))
      ORDER BY t.created_at DESC`
  ).all(new Date().toISOString(), new Date().toISOString()) as any[];

  const mbRows = mailboxes.map((m) => `<tr><td>${esc(m.label)}</td><td>${esc(m.imap_host)}:${m.imap_port}</td><td>${esc(m.imap_username)}</td>
    <td>${m.drafts_folder ? esc(m.drafts_folder) : '<span class="small">not set</span>'}</td><td><a href="/mailboxes/${esc(m.id)}">Manage</a></td></tr>`).join("");
  const clRows = clients.map((c) => `<tr><td>${esc(c.client_name || "(unnamed)")}<div class="small">${esc(c.client_id)}</div></td>
    <td>${c.disabled ? "disabled" : "active"}</td><td><a href="/clients/${esc(c.client_id)}">Grants</a>
    ${post(req, `/clients/${encodeURIComponent(c.client_id)}/${c.disabled ? "enable" : "disable"}`, c.disabled ? "Enable" : "Disable")}</td></tr>`).join("");
  const tkRows = tokens.map((t) => `<tr><td>${esc(t.client_name || t.client_id)}</td><td>${esc(t.scopes)}</td><td class="small">${esc(t.created_at)}</td>
    <td class="small">${esc(t.expires_at)}</td><td>${post(req, `/tokens/${encodeURIComponent(t.id)}/revoke`, "Revoke", "btn-danger")}</td></tr>`).join("");

  send(res, "Dashboard", `${flash(req)}
  <div class="card"><h2>Mailboxes</h2>
    ${mailboxes.length ? `<table><tr><th>Label</th><th>Server</th><th>User</th><th>Drafts</th><th></th></tr>${mbRows}</table>` : "<p>No mailboxes yet.</p>"}
    <a class="btn" href="/mailboxes/new">Add mailbox</a></div>
  <div class="card"><h2>Clients</h2>
    ${clients.length ? `<table><tr><th>Client</th><th>Status</th><th></th></tr>${clRows}</table>` : "<p>No clients registered.</p>"}
    ${config.registrationMode === "admin" ? `<h3 style="margin-top:16px">Add client</h3>
    <form method="POST" action="/clients">${csrf(req)}
      <label>Name</label><input type="text" name="client_name" maxlength="100" required>
      <label>Redirect URIs (one per line; https or http://localhost)</label><textarea name="redirect_uris" rows="3" style="width:100%" required></textarea>
      <button type="submit">Create client</button></form>`
      : `<p class="small">Clients register themselves dynamically (REGISTRATION_MODE=dynamic). Registration grants no access.</p>`}</div>
  <div class="card"><h2>Active tokens</h2>
    ${tokens.length ? `<table><tr><th>Client</th><th>Scopes</th><th>Issued</th><th>Access expires</th><th></th></tr>${tkRows}</table>` : "<p>No active tokens.</p>"}</div>`);
});

// ---------------- Mailboxes ----------------
function mailboxForm(req: Request, opts: { action: string; m?: { label: string; imap_host: string; imap_port: number; imap_username: string }; edit: boolean }) {
  const m = opts.m;
  return `<form method="POST" action="${esc(opts.action)}" autocomplete="off">${csrf(req)}
    <label>Label</label><input type="text" name="label" maxlength="100" required value="${esc(m?.label ?? "")}">
    <label>IMAP host</label><input type="text" name="host" maxlength="253" required value="${esc(m?.imap_host ?? "")}">
    <label>Port (TLS)</label><input type="number" name="port" min="1" max="65535" required value="${m?.imap_port ?? 993}">
    <label>Username</label><input type="text" name="username" maxlength="320" required value="${esc(m?.imap_username ?? "")}">
    <label>Password${opts.edit ? " (leave empty to keep the saved password)" : ""}</label>
    <input type="password" name="password" autocomplete="new-password" ${opts.edit ? "" : "required"}>
    <button type="submit">${opts.edit ? "Save" : "Add mailbox"}</button></form>`;
}

router.get("/mailboxes/new", (req, res) => {
  send(res, "Add mailbox", `${flash(req)}<div class="card"><h2>Add mailbox</h2>${mailboxForm(req, { action: "/mailboxes", edit: false })}
    <p class="small">Connections use TLS with certificate validation. Test the connection after saving.</p></div>`);
});

router.post("/mailboxes", (req, res) => {
  const i = { label: str(req.body.label, 100), host: str(req.body.host, 253), port: parseInt(str(req.body.port, 6), 10), username: str(req.body.username, 320), password: typeof req.body.password === "string" ? req.body.password : "" };
  const bad = validateMailboxInput(i, true);
  if (bad) return back(res, "/mailboxes/new", "err", bad);
  const m = createMailbox(i);
  back(res, `/mailboxes/${m.id}`, "msg", "Mailbox saved. Run the connection test, then choose the Drafts folder.");
});

function renderMailbox(req: Request, res: Response, id: string, test?: { ok: boolean; message: string; folders: string[] }) {
  const m = getMailbox(id);
  if (!m) return res.status(404).send(layout("Not found", `<div class="card"><h2>Mailbox not found</h2><a href="/dashboard">Back</a></div>`, "admin"));
  const folderForm = test?.ok
    ? `<form method="POST" action="/mailboxes/${esc(m.id)}/drafts">${csrf(req)}
        <label>Drafts folder</label>
        <select name="drafts_folder">${test.folders.map((f) => `<option value="${esc(f)}"${f === m.drafts_folder ? " selected" : ""}>${esc(f)}</option>`).join("")}</select>
        <button type="submit">Save Drafts folder</button></form>`
    : `<p class="small">Run the connection test to choose the Drafts folder from the server's folder list.</p>`;
  send(res, m.label, `${flash(req)}
  <div class="card"><h2>${esc(m.label)}</h2>${mailboxForm(req, { action: `/mailboxes/${m.id}`, m, edit: true })}</div>
  <div class="card"><h2>Connection and Drafts folder</h2>
    <p>Current Drafts folder: <strong>${m.drafts_folder ? esc(m.drafts_folder) : "not set"}</strong></p>
    ${test ? `<div class="${test.ok ? "success" : "error"}">${esc(test.message)}</div>` : ""}
    ${post(req, `/mailboxes/${m.id}/test`, "Test connection")}
    ${folderForm}</div>
  <div class="card"><h2>Remove</h2><p class="small">Removes this configuration and all its grants. Mail on the server is not touched.</p>
    ${post(req, `/mailboxes/${m.id}/delete`, "Delete mailbox", "btn-danger", "Delete this mailbox configuration?")}</div>`);
}

router.get("/mailboxes/:id", (req, res) => renderMailbox(req, res, req.params.id));

router.post("/mailboxes/:id", (req, res) => {
  const id = req.params.id;
  const i = { label: str(req.body.label, 100), host: str(req.body.host, 253), port: parseInt(str(req.body.port, 6), 10), username: str(req.body.username, 320), password: typeof req.body.password === "string" ? req.body.password : "" };
  const bad = validateMailboxInput(i, false);
  if (bad) return back(res, `/mailboxes/${id}`, "err", bad);
  if (!updateMailbox(id, i)) return res.status(404).send("Not found");
  back(res, `/mailboxes/${id}`, "msg", "Saved. If host, port or username changed, re-test and re-select the Drafts folder.");
});

router.post("/mailboxes/:id/test", async (req, res) => {
  if (!getMailbox(req.params.id)) return res.status(404).send("Not found");
  renderMailbox(req, res, req.params.id, await testMailbox(req.params.id));
});

router.post("/mailboxes/:id/drafts", async (req, res) => {
  const id = req.params.id;
  const folder = str(req.body.drafts_folder, 255);
  if (!getMailbox(id)) return res.status(404).send("Not found");
  if (!folder || /[\x00-\x1f]/.test(folder)) return back(res, `/mailboxes/${id}`, "err", "Choose a folder");
  // must be a folder that really exists on the server
  const t = await testMailbox(id);
  if (!t.ok) return renderMailbox(req, res, id, t);
  if (!t.folders.includes(folder)) return back(res, `/mailboxes/${id}`, "err", "That folder does not exist on the server");
  setDraftsFolder(id, folder);
  back(res, `/mailboxes/${id}`, "msg", "Drafts folder saved.");
});

router.post("/mailboxes/:id/delete", (req, res) => {
  deleteMailbox(req.params.id);
  back(res, "/dashboard", "msg", "Mailbox configuration removed.");
});

// ---------------- Clients & grants ----------------
router.post("/clients", (req, res) => {
  if (config.registrationMode !== "admin") return res.status(403).send("Clients are registered dynamically");
  const name = str(req.body.client_name, 100);
  const uris = str(req.body.redirect_uris, 4000).split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  if (!name || uris.length === 0 || uris.length > 10 || !uris.every(validRedirectUri)) {
    return back(res, "/dashboard", "err", "Name and 1-10 valid redirect URIs required (https, or http on localhost)");
  }
  const id = randomUUID();
  getDb().prepare("INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)").run(id, name, JSON.stringify(uris));
  back(res, `/clients/${id}`, "msg", `Client created. client_id: ${id}`);
});

router.get("/clients/:id", (req, res) => {
  const db = getDb();
  const c = db.prepare("SELECT client_id, client_name, redirect_uris, disabled FROM oauth_clients WHERE client_id = ?").get(req.params.id) as any;
  if (!c) return res.status(404).send(layout("Not found", `<div class="card"><h2>Client not found</h2></div>`, "admin"));
  const mailboxes = listMailboxes();
  const granted = new Set((db.prepare("SELECT mailbox_id, capability FROM grants WHERE client_id = ?").all(c.client_id) as any[]).map((g) => `${g.mailbox_id}:${g.capability}`));
  let uris: string[] = [];
  try { uris = JSON.parse(c.redirect_uris); } catch { /* ignore */ }
  const rows = mailboxes.map((m) => `<tr><td>${esc(m.label)}</td>${CAPABILITIES.map((cap) =>
    `<td><input type="checkbox" name="g_${esc(m.id)}_${cap}" value="1"${granted.has(`${m.id}:${cap}`) ? " checked" : ""} aria-label="${cap} on ${esc(m.label)}"></td>`).join("")}</tr>`).join("");
  send(res, "Client", `${flash(req)}
  <div class="card"><h2>${esc(c.client_name || "(unnamed)")}</h2>
    <p class="small">client_id: ${esc(c.client_id)} &middot; ${c.disabled ? "disabled" : "active"}</p>
    <p class="small">Redirect URIs: ${uris.map(esc).join(", ")}</p></div>
  <div class="card"><h2>Grants</h2>
    <p class="small">Removing a grant applies on the next call, including for existing tokens. Adding a capability the client's tokens were not consented for needs a new authorization.</p>
    ${mailboxes.length ? `<form method="POST" action="/clients/${esc(c.client_id)}/grants">${csrf(req)}
      <table><tr><th>Mailbox</th>${CAPABILITIES.map((x) => `<th>${x}</th>`).join("")}</tr>${rows}</table><button type="submit">Save grants</button></form>` : "<p>No mailboxes configured.</p>"}</div>`);
});

router.post("/clients/:id/grants", (req, res) => {
  const db = getDb();
  const c = db.prepare("SELECT client_id FROM oauth_clients WHERE client_id = ?").get(req.params.id);
  if (!c) return res.status(404).send("Not found");
  const mailboxes = listMailboxes();
  db.transaction(() => {
    db.prepare("DELETE FROM grants WHERE client_id = ?").run(req.params.id);
    const ins = db.prepare("INSERT INTO grants (client_id, mailbox_id, capability) VALUES (?, ?, ?)");
    for (const m of mailboxes) for (const cap of CAPABILITIES as Capability[]) if (req.body[`g_${m.id}_${cap}`]) ins.run(req.params.id, m.id, cap);
  })();
  back(res, `/clients/${encodeURIComponent(req.params.id)}`, "msg", "Grants saved.");
});

for (const [action, val] of [["disable", 1], ["enable", 0]] as const) {
  router.post(`/clients/:id/${action}`, (req, res) => {
    const db = getDb();
    db.prepare("UPDATE oauth_clients SET disabled = ? WHERE client_id = ?").run(val, req.params.id);
    if (val) db.prepare("UPDATE oauth_tokens SET revoked = 1 WHERE client_id = ?").run(req.params.id);
    back(res, "/dashboard", "msg", val ? "Client disabled and its tokens revoked." : "Client enabled.");
  });
}

// ---------------- Tokens ----------------
router.post("/tokens/:id/revoke", (req, res) => {
  getDb().prepare("UPDATE oauth_tokens SET revoked = 1 WHERE id = ?").run(req.params.id);
  back(res, "/dashboard", "msg", "Token revoked.");
});

export default router;
