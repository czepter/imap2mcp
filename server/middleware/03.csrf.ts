import { defineEventHandler } from "h3";
import { enforceCsrf } from "../utils/csrf";

export default defineEventHandler(async (event) => {
  await enforceCsrf(event);
});
