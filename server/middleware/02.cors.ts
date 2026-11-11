import { defineEventHandler } from "h3";
import { applyCors, isCorsPath } from "../utils/cors";
import { pathnameOf } from "../utils/csrf";

export default defineEventHandler((event) => {
  if (isCorsPath(pathnameOf(event))) applyCors(event); // answers OPTIONS preflights itself (204)
});
