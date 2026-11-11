import { apiError } from "../../utils/apiError";

// Unclaimed path below /api: the admin API's JSON 404 for every method (the SPA fallback must not answer here).
export default defineEventHandler(() => apiError(404, "not_found", "Not found"));
