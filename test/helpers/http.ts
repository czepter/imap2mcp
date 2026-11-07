/** Tiny cookie-jar HTTP client for driving the admin UI like a browser would (no redirects followed). */
export class Browser {
  private jar = new Map<string, string>();
  constructor(public base: string) {}

  private cookieHeader(): string {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  private store(res: Response) {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(";");
      const i = pair.indexOf("=");
      const name = pair.slice(0, i).trim();
      const val = pair.slice(i + 1).trim();
      if (/;\s*expires=Thu, 01 Jan 1970/i.test(c) || val === "") this.jar.delete(name);
      else this.jar.set(name, val);
    }
  }
  async req(method: string, path: string, form?: Record<string, string>, headers: Record<string, string> = {}): Promise<Response> {
    const h: Record<string, string> = { ...headers };
    const ck = this.cookieHeader();
    if (ck) h.cookie = ck;
    let body: string | undefined;
    if (form) {
      h["content-type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams(form).toString();
    }
    const res = await fetch(this.base + path, { method, headers: h, body, redirect: "manual" });
    this.store(res);
    return res;
  }
  get(path: string) {
    return this.req("GET", path);
  }
  post(path: string, form: Record<string, string>, headers?: Record<string, string>) {
    return this.req("POST", path, form, headers);
  }
  /** GET a page and return its CSRF token. */
  async csrf(path: string): Promise<string> {
    const html = await (await this.get(path)).text();
    const m = /name="_csrf" value="([^"]+)"/.exec(html);
    if (!m) throw new Error(`no csrf token on ${path}: ${html.slice(0, 200)}`);
    return m[1];
  }
  /** GET csrf from `pagePath`, then POST form (+ _csrf) to `action`. */
  async postWithCsrf(pagePath: string, action: string, form: Record<string, string>) {
    const _csrf = await this.csrf(pagePath);
    return this.post(action, { _csrf, ...form });
  }
  cookies(): string {
    return this.cookieHeader();
  }
}

export function location(res: Response): string {
  const l = res.headers.get("location");
  if (!l) throw new Error(`expected redirect, got ${res.status}`);
  return l;
}
