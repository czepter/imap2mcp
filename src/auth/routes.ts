import { Router, type Request, type Response } from "express";
import { randomBytes, timingSafeEqual } from "crypto";
import { getDb } from "../db/database.js";
import { hashPassword, verifyPassword } from "./password.js";
import { adminExists, safeReturnTo } from "./admin.js";
import { csrfField, createRateLimiter } from "../security/index.js";
import { config } from "../config.js";

const router = Router();
const MIN_PASSWORD = 12;

let bootstrapToken: string | undefined;

/** Called at startup. Prints the one-time bootstrap token if no admin exists yet. */
export function initBootstrap(): void {
  if (adminExists()) return;
  bootstrapToken = config.adminBootstrapToken || randomBytes(24).toString("base64url");
  console.log("========================================");
  console.log("  First run: no admin configured.");
  console.log(`  Open ${config.baseUrl}/setup and enter this one-time bootstrap token:`);
  console.log(`  ${bootstrapToken}`);
  console.log("========================================");
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function page(title: string, body: string): string {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} - IMAP Bridge</title>
<style>body{font-family:system-ui,sans-serif;background:#f5f5f5;color:#333;margin:0}.c{max-width:420px;margin:60px auto;background:#fff;padding:24px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
label{display:block;margin-top:12px;font-weight:500}input{width:100%;box-sizing:border-box;padding:8px;border:1px solid #ccc;border-radius:6px}
button{margin-top:16px;background:#2563eb;color:#fff;border:0;padding:10px 20px;border-radius:6px;cursor:pointer}.e{color:#b91c1c;background:#fef2f2;padding:8px;border-radius:6px}</style></head>
<body><div class="c"><h2>${esc(title)}</h2>${body}</div></body></html>`;
}

const err = (m?: string) => (m ? `<div class="e">${esc(m)}</div>` : "");

const loginLimiter = createRateLimiter({ windowMs: 15 * 60_000, max: 10, message: "Too many attempts, try again later" });
const setupLimiter = createRateLimiter({ windowMs: 15 * 60_000, max: 10, message: "Too many attempts, try again later" });

function eq(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// ---- /setup (404 once an admin exists) ----
router.use("/setup", (req, res, next) => {
  if (adminExists() || !bootstrapToken) return res.status(404).type("text/plain").send("Not found");
  next();
});

function setupForm(req: Request, error?: string): string {
  return page(
    "Initial setup",
    `${err(error)}<form method="POST" action="/setup">${csrfField(req)}
<label>Bootstrap token (printed in the server log)</label><input type="password" name="token" required autocomplete="off">
<label>Admin password (min ${MIN_PASSWORD} chars)</label><input type="password" name="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password">
<label>Repeat password</label><input type="password" name="password2" required minlength="${MIN_PASSWORD}" autocomplete="new-password">
<button type="submit">Create admin</button></form>`
  );
}

router.get("/setup", (req, res) => res.send(setupForm(req)));

router.post("/setup", setupLimiter, async (req: Request, res: Response) => {
  const { token, password, password2 } = req.body ?? {};
  if (typeof token !== "string" || !bootstrapToken || !eq(token, bootstrapToken)) {
    return res.status(403).send(setupForm(req, "Invalid bootstrap token"));
  }
  if (typeof password !== "string" || password.length < MIN_PASSWORD) {
    return res.status(400).send(setupForm(req, `Password must be at least ${MIN_PASSWORD} characters`));
  }
  if (password !== password2) return res.status(400).send(setupForm(req, "Passwords do not match"));
  const hash = await hashPassword(password);
  try {
    getDb().prepare("INSERT INTO admin (id, password_hash) VALUES (1, ?)").run(hash);
  } catch {
    return res.status(404).type("text/plain").send("Not found");
  }
  bootstrapToken = undefined;
  req.session.regenerate((e) => {
    if (e) return res.status(500).type("text/plain").send("Session error");
    req.session.admin = true;
    res.redirect("/");
  });
});

// ---- /login, /logout ----
router.get("/login", (req, res) => {
  if (!adminExists()) return res.redirect("/setup");
  res.send(
    page("Admin login", `${err(req.query.error ? "Invalid password" : undefined)}<form method="POST" action="/login">${csrfField(req)}
<label>Password</label><input type="password" name="password" required autofocus autocomplete="current-password">
<button type="submit">Login</button></form>`)
  );
});

router.post("/login", loginLimiter, async (req: Request, res: Response) => {
  const row = getDb().prepare("SELECT password_hash FROM admin WHERE id = 1").get() as { password_hash: string } | undefined;
  const pw = req.body?.password;
  const ok = row && typeof pw === "string" && pw.length <= 1024 && (await verifyPassword(pw, row.password_hash));
  if (!ok) return res.redirect("/login?error=1");
  const returnTo = safeReturnTo(req.session.returnTo);
  req.rateLimit?.reset();
  req.session.regenerate((e) => {
    if (e) return res.status(500).type("text/plain").send("Session error");
    req.session.admin = true;
    res.redirect(returnTo ?? "/");
  });
});

router.get("/logout", (req, res) => {
  res.send(page("Logout", `<form method="POST" action="/logout">${csrfField(req)}<button type="submit">Log out</button></form>`));
});

router.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("imap2mcp.sid");
    res.redirect("/login");
  });
});

export default router;
