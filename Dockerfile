# --- Builder stage ---
FROM golang:1.25.9 AS builder

WORKDIR /app

# Cache modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/connector

# --- Development stage (with hot reload) ---
FROM golang:1.25.9 AS dev

WORKDIR /app

# Install Air for hot reload
RUN go install github.com/air-verse/air@latest

EXPOSE 8080

# Note: Source code will be mounted as a volume at runtime
# CMD will be overridden in docker-compose.yml

# --- Production runtime stage ---
FROM alpine:latest AS production

WORKDIR /app

RUN apk --no-cache add ca-certificates

# Copy binary from builder stage
COPY --from=builder /app/server .

ENV ENV_LEVEL=production

EXPOSE 8080

CMD ["./server"]
