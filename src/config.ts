const isProduction = process.env.NODE_ENV === "production";

if (isProduction && !process.env.ENCRYPTION_KEY) {
  console.error("FATAL: ENCRYPTION_KEY must be set in production");
  process.exit(1);
}
if (isProduction && !process.env.SESSION_SECRET) {
  console.error("FATAL: SESSION_SECRET must be set in production");
  process.exit(1);
}

if (!process.env.ENCRYPTION_KEY) {
  console.warn("WARNING: Using default ENCRYPTION_KEY — set ENCRYPTION_KEY env var for production!");
}
if (!process.env.SESSION_SECRET) {
  console.warn("WARNING: Using default SESSION_SECRET — set SESSION_SECRET env var for production!");
}

export const config = {
  baseUrl: process.env.BASE_URL || "http://localhost:3000",
  port: parseInt(process.env.PORT || "3000", 10),
  encryptionKey: process.env.ENCRYPTION_KEY || "0".repeat(64),
  sessionSecret: process.env.SESSION_SECRET || "dev-session-secret",
  corsOrigin: process.env.CORS_ORIGIN || undefined,
};
