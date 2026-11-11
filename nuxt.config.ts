import tailwindcss from "@tailwindcss/vite";

export default defineNuxtConfig({
  compatibilityDate: "2025-07-15",
  ssr: false,
  telemetry: false,
  devtools: { enabled: false },
  modules: ["shadcn-nuxt"],
  css: ["~/assets/css/main.css"],
  vite: { plugins: [tailwindcss()] },
  shadcn: { prefix: "", componentDir: "./app/components/ui" },
  // The domain code (server/core) was written under plain `strict`; Nuxt additionally enables noUncheckedIndexedAccess.
  typescript: {
    strict: true,
    tsConfig: { compilerOptions: { noUncheckedIndexedAccess: false } },
    nodeTsConfig: { compilerOptions: { noUncheckedIndexedAccess: false } },
    sharedTsConfig: { compilerOptions: { noUncheckedIndexedAccess: false } },
  },
  app: {
    head: {
      title: "IMAP Bridge",
      htmlAttrs: { lang: "en" },
      meta: [{ name: "viewport", content: "width=device-width, initial-scale=1" }, { name: "robots", content: "noindex" }],
    },
  },
  nitro: {
    preset: "node-server",
    errorHandler: "~~/server/error",
    // Config is read from process.env at runtime (server/core/config.ts), never baked in at build time.
    experimental: { tasks: false },
  },
});
