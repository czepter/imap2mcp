import { notFoundBody } from "../../utils/oauthProtocol";

// Unclaimed path below /healthz: JSON 404 for every method (the SPA fallback must not answer here).
export default defineEventHandler((event) => notFoundBody(event));
