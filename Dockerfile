# Multi-stage build for MCP SandboxRunner Server

# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make ca-certificates tzdata

# Set working directory
WORKDIR /src

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
ARG VERSION=docker
ARG COMMIT=unknown
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /bin/mcp-sandboxd \
    ./cmd/mcp-sandboxd

# Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    runc \
    iptables \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 -S sandboxrunner && \
    adduser -u 1000 -S sandboxrunner -G sandboxrunner

# Create necessary directories
RUN mkdir -p /app/config /tmp/sandboxrunner && \
    chown -R sandboxrunner:sandboxrunner /app /tmp/sandboxrunner

# Copy binary from builder
COPY --from=builder /bin/mcp-sandboxd /usr/local/bin/mcp-sandboxd

# Copy default configuration
COPY config/mcp-sandboxd.yaml /app/config/

# Set working directory
WORKDIR /app

# Switch to non-root user
USER sandboxrunner

# Expose port (if HTTP mode is used)
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD [ "/usr/local/bin/mcp-sandboxd", "config", "validate", "--config", "/app/config/mcp-sandboxd.yaml" ]

# Default command
CMD ["/usr/local/bin/mcp-sandboxd", "--config", "/app/config/mcp-sandboxd.yaml"]

# Labels
LABEL maintainer="SandboxRunner Team"
LABEL description="MCP SandboxRunner Server - Sandbox management via Model Context Protocol"
LABEL version="${VERSION}"