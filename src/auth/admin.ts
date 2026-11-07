import type { Request, Response, NextFunction } from "express";
import { getDb } from "../db/database.js";

declare module "express-session" {
  interface SessionData {
    admin?: boolean;
    returnTo?: string;
  }
}

export function adminExists(): boolean {
  return !!getDb().prepare("SELECT 1 FROM admin WHERE id = 1").get();
}

/** Only allow same-site relative paths. */
export function safeReturnTo(v: unknown): string | undefined {
  return typeof v === "string" && v.startsWith("/") && !v.startsWith("//") && !v.includes("\\") ? v : undefined;
}

/** Require a logged-in owner session. GET -> redirect to /login (remembering the URL); others -> 401. */
export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (req.session?.admin === true && adminExists()) return next();
  if (req.method === "GET" || req.method === "HEAD") {
    req.session.returnTo = req.originalUrl;
    return res.redirect("/login");
  }
  res.status(401).type("text/plain").send("Authentication required");
}
