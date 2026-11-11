import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "sqlite",
  schema: "./server/core/db/schema.ts",
  out: "./drizzle",
});
