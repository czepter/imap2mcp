import { defineNitroPlugin } from "nitropack/runtime";
import { applyBaseHeaders, applyRequestId, applySpaCsp } from "../utils/securityHeaders";

/**
 * Nitro serves public assets (index.html, /_nuxt/*) from a handler that runs before every server middleware, so the
 * request id and security headers are applied from the `request` hook as well, and the SPA document's CSP (inline
 * script hashes) is derived from the exact body about to be sent.
 */
export default defineNitroPlugin((nitroApp) => {
  nitroApp.hooks.hook("request", (event) => {
    applyRequestId(event);
    applyBaseHeaders(event);
  });
  nitroApp.hooks.hook("beforeResponse", (event, response) => {
    applySpaCsp(event, response?.body);
  });
});
