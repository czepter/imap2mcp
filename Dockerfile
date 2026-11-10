FROM golang:1.27-alpine AS sidecar
WORKDIR /src/sidecar
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod
COPY sidecar/go.mod sidecar/go.sum ./
RUN go mod download
COPY sidecar/cmd/ ./cmd/
COPY sidecar/internal/ ./internal/
RUN go build -trimpath -ldflags="-s -w" -o /out/sidecar ./cmd/sidecar

FROM node:26-slim AS build
WORKDIR /app
# better-sqlite3 has no prebuilt binary for every Node patch release; fall back to compiling it here.
# The toolchain stays in this stage only.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
COPY drizzle.config.ts ./
COPY drizzle/ ./drizzle/
RUN npm run build && npm prune --omit=dev && npm cache clean --force

FROM node:26-slim
WORKDIR /app
ENV NODE_ENV=production DATA_DIR=/app/data
RUN apt-get update && apt-get install -y --no-install-recommends dumb-init ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/package*.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/drizzle ./drizzle
COPY --from=sidecar /out/sidecar ./sidecar/bin/sidecar
RUN mkdir -p /app/data && chown node:node /app/data
VOLUME /app/data
EXPOSE 3000
USER node
# Liveness only (GET /healthz). Readiness (/readyz) is for the operator and the reverse proxy; a 503 there
# (for example a wrong key) must not make the orchestrator restart-loop the container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
