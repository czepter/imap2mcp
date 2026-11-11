import { apiError } from "../../utils/apiError";

// The bare API root (/api and /api/): JSON 404 for every method, never the SPA document.
export default defineEventHandler(() => apiError(404, "not_found", "Not found"));
