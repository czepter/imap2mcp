import type { Request, Response, NextFunction } from "express";

export function securityHeaders(opts: { https: boolean }) {
  return (_req: Request, res: Response, next: NextFunction) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cache-Control", "no-store");
    // No form-action: browsers apply it to redirects after form POST, which breaks the OAuth consent redirect.
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    );
    if (opts.https) res.setHeader("Strict-Transport-Security", "max-age=31536000");
    next();
  };
}
