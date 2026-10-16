# golang:1.27.2 — multi-architecture manifest pinned for reproducible builds.
ARG GO_IMAGE=golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8

# --- Builder stage ---
FROM ${GO_IMAGE} AS builder

WORKDIR /app

# Cache modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/connector

# --- Development stage (with hot reload) ---
FROM ${GO_IMAGE} AS dev

WORKDIR /app

# Install Air for hot reload
RUN go install github.com/air-verse/air@v1.66.0

EXPOSE 8080

# Note: Source code will be mounted as a volume at runtime
# CMD will be overridden in docker-compose.yml

# --- Production runtime stage ---
FROM scratch AS production

WORKDIR /app

# Preserve system trust roots for controller, telemetry, and upstream TLS.
COPY --from=builder --chown=65532:65532 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy binary from builder stage
COPY --from=builder --chown=65532:65532 /app/server .

USER 65532:65532

ENV ENV_LEVEL=production

EXPOSE 8080

CMD ["./server"]
