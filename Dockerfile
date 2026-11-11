FROM golang:1.25-alpine AS sidecar
WORKDIR /src/sidecar
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod
COPY sidecar/go.mod sidecar/go.sum ./
RUN go mod download
COPY sidecar/cmd/ ./cmd/
COPY sidecar/internal/ ./internal/
RUN go build -trimpath -ldflags="-s -w" -o /out/sidecar ./cmd/sidecar

FROM node:26-slim AS build
WORKDIR /app
# better-sqlite3 ships prebuilt binaries (linux x64/arm64, glibc and musl) inside the npm package, so no compiler
# toolchain is needed. If a future release drops them, install python3 make g++ here (never in the runtime stage).
# --ignore-scripts: the postinstall hook (nuxt prepare) needs the sources, which are copied after the dependency layer;
# `nuxt build` prepares the project itself.
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY nuxt.config.ts tsconfig.json components.json ./
COPY app/ ./app/
COPY shared/ ./shared/
COPY server/ ./server/
COPY public/ ./public/
COPY drizzle/ ./drizzle/
COPY scripts/build-cli.mjs ./scripts/build-cli.mjs
# `npm run build` = nuxt build (-> .output/: SPA in public/, Nitro server in server/, native modules traced into
# server/node_modules) + the standalone audit export CLI (-> dist/audit/cli.js).
RUN npm run build

FROM node:26-slim
WORKDIR /app
# HOST: Nitro's listen address (NITRO_HOST wins if set). The listen port is PORT (default 3000), as before.
ENV NODE_ENV=production DATA_DIR=/app/data HOST=0.0.0.0
RUN apt-get update && apt-get install -y --no-install-recommends dumb-init ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/.output ./.output
COPY --from=build /app/dist ./dist
COPY --from=build /app/drizzle ./drizzle
COPY --from=sidecar /out/sidecar ./sidecar/bin/sidecar
# dist/audit/cli.js is a standalone bundle that only needs the native better-sqlite3 addon; resolve it from the
# dependencies Nitro already traced into .output instead of shipping a second copy.
RUN ln -s .output/server/node_modules node_modules \
 && mkdir -p /app/data && chown node:node /app/data
VOLUME /app/data
EXPOSE 3000
USER node
# Liveness only (GET /healthz). Readiness (/readyz) is for the operator and the reverse proxy; a 503 there
# (for example a wrong key) must not make the orchestrator restart-loop the container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", ".output/server/index.mjs"]
