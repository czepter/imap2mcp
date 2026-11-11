import { defineEventHandler } from "h3";
import { applyRequestId } from "../utils/securityHeaders";

export default defineEventHandler((event) => {
  applyRequestId(event);
});
