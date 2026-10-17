# Keep Go, Node, and Trivy versions aligned with mise.toml.
FROM node:24.8.0-bookworm-slim AS frontend
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.8-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY web/embed.go ./web/embed.go
COPY --from=frontend /src/web/dist ./web/dist
RUN CGO_ENABLED=1 go build -trimpath -o /out/kbomination ./cmd/kbomination

FROM debian:bookworm-slim
COPY --from=ghcr.io/jdx/mise:2026.9.11 /usr/local/bin/mise /usr/local/bin/mise
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git libstdc++6 libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*
ENV MISE_DATA_DIR=/opt/mise \
    MISE_CONFIG_DIR=/home/kbomination/.config/mise \
    MISE_CACHE_DIR=/home/kbomination/.cache/mise \
    MISE_STATE_DIR=/home/kbomination/.local/state/mise \
    HOME=/home/kbomination
RUN useradd --create-home --uid 1000 kbomination \
    && mkdir -p /data /opt/mise \
    && chown -R kbomination:kbomination /data /opt/mise /home/kbomination
USER kbomination
RUN mise install trivy@0.76.0 \
    && mise exec trivy@0.76.0 -- trivy --version
ENV MISE_OFFLINE=true
COPY --from=backend /out/kbomination /usr/local/bin/kbomination
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["kbomination"]
CMD ["serve", "--db", "/data/kbomination.duckdb"]
