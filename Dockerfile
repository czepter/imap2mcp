FROM golang:1.23-alpine AS sidecar
WORKDIR /src/sidecar
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod
COPY sidecar/go.mod sidecar/go.sum ./
RUN go mod download
COPY sidecar/cmd/ ./cmd/
COPY sidecar/internal/ ./internal/
RUN go build -trimpath -ldflags="-s -w" -o /out/sidecar ./cmd/sidecar

FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
COPY drizzle.config.ts ./
COPY drizzle/ ./drizzle/
RUN npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production DATA_DIR=/app/data
RUN apt-get update && apt-get install -y --no-install-recommends dumb-init && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY --from=build /app/drizzle ./drizzle
COPY --from=sidecar /out/sidecar ./sidecar/bin/sidecar
RUN mkdir -p /app/data && chown node:node /app/data
VOLUME /app/data
EXPOSE 3000
USER node
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
