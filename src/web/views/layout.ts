import { escapeHtml } from "./escapeHtml.js";

export function layout(title: string, body: string, username?: string): string {
  return `<!DOCTYPE html>
<html><head>
<title>${escapeHtml(title)} - IMAP Bridge</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; }
  nav { background: #1e293b; color: white; padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; }
  nav a { color: #93c5fd; text-decoration: none; margin-left: 16px; }
  nav a:hover { color: white; }
  .container { max-width: 700px; margin: 40px auto; padding: 0 20px; }
  .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 20px; }
  h1, h2 { margin-bottom: 16px; }
  label { display: block; margin-bottom: 4px; font-weight: 500; margin-top: 12px; }
  input[type="text"], input[type="password"], input[type="number"], select {
    width: 100%; padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 14px;
  }
  button, .btn { background: #2563eb; color: white; border: none; padding: 10px 20px; border-radius: 6px;
    cursor: pointer; font-size: 14px; display: inline-block; text-decoration: none; margin-top: 16px; }
  button:hover, .btn:hover { background: #1d4ed8; }
  .btn-danger { background: #dc2626; }
  .btn-danger:hover { background: #b91c1c; }
  .error { color: #dc2626; background: #fef2f2; padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; }
  .success { color: #16a34a; background: #f0fdf4; padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #e5e7eb; }
  th { background: #f9fafb; font-weight: 600; }
  .small { font-size: 12px; color: #6b7280; }
</style>
</head><body>
<nav>
  <strong>IMAP Bridge</strong>
  <div>
    ${username
      ? `<span>${escapeHtml(username)}</span><a href="/dashboard">Dashboard</a><a href="/logout">Logout</a>`
      : `<a href="/login">Login</a>`
    }
  </div>
</nav>
<div class="container">
  ${body}
</div>
</body></html>`;
}
