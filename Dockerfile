# golang:1.25.13 — multi-architecture manifest pinned for reproducible builds.
ARG GO_IMAGE=golang:1.25.13@sha256:cbff9d1a9041b316010f2da6b701b6c0d597718cb90928c85eb597334a0d23d4
# Envoy carries raw pipes over reverse tunnels. The reverse-tunnel extensions
# are alpha and outside Envoy's security release process, so the version is
# pinned and every upgrade is gated on the tunnel conformance suites.
# envoyproxy/envoy:distroless-v1.39.2, multi-architecture manifest.
ARG ENVOY_IMAGE=envoyproxy/envoy:distroless-v1.39.2@sha256:dced08cf7c472e1a1d067f906878266078eeeb63c110b4961882c039a622853a

# --- Builder stage ---
FROM ${GO_IMAGE} AS builder

WORKDIR /app

# Cache modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build statically linked binary
ARG VERSION=""
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X github.com/InteractionLabs/traversal-connector/internal/buildinfo.version=${VERSION}" \
    -o server ./cmd/connector

# --- Development stage (with hot reload) ---
FROM ${GO_IMAGE} AS dev

WORKDIR /app

# Install Air for hot reload
RUN go install github.com/air-verse/air@v1.66.0

EXPOSE 8080

# Note: Source code will be mounted as a volume at runtime
# CMD will be overridden in docker-compose.yml

# --- Production runtime stage ---
# Envoy's distroless image: glibc for Envoy, no shell, nonroot 65532.
FROM ${ENVOY_IMAGE} AS production

WORKDIR /app

# Preserve system trust roots for controller, telemetry, and upstream TLS.
COPY --from=builder --chown=65532:65532 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy binary from builder stage
COPY --from=builder --chown=65532:65532 /app/server .

USER 65532:65532

ENV ENV_LEVEL=production
ENV TRAVERSAL_ENVOY_PATH=/usr/local/bin/envoy

EXPOSE 8080

ENTRYPOINT ["/app/server"]
