import { defineEventHandler } from "h3";
import { applyBaseHeaders } from "../utils/securityHeaders";

// Static files bypass middleware in Nitro; server/plugins/00.security.ts applies the same function from a `request` hook.
export default defineEventHandler((event) => {
  applyBaseHeaders(event);
});
