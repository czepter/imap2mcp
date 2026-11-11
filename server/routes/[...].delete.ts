import { apiError } from "../utils/apiError";
import { notFoundBody } from "../utils/oauthProtocol";

// Reached only when no route claimed this write (a real route with a matching method always wins in h3's router):
// below /api that means an unknown path or a wrong method on a known path => the API's JSON error shape;
// elsewhere Express answered 404 and Nuxt's SPA renderer would otherwise answer the HTML document.
export default defineEventHandler((event) => {
  const p = event.path.split("?")[0];
  if (p === "/api" || p.startsWith("/api/")) return apiError(404, "not_found", "Not found");
  return notFoundBody(event);
});
