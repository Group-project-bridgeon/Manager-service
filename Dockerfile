# ------------------------------------------------------------------------------
# Stage 1: Build static Go binary
# ------------------------------------------------------------------------------
FROM golang:alpine AS builder

WORKDIR /build

# Install CA certificates and tzdata needed in runtime image
RUN apk --no-cache add ca-certificates tzdata

# Leverage Docker cache for dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build statically
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/server ./cmd/server

# ------------------------------------------------------------------------------
# Stage 2: Minimal, secure runtime image
# ------------------------------------------------------------------------------
FROM alpine:3.20

# Create unprivileged user
RUN adduser -D -u 10001 -s /sbin/nologin appuser

# Copy SSL certificates and timezone data from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy compiled binary from builder
COPY --from=builder /bin/server /usr/local/bin/server

# Run as unprivileged user
USER appuser

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/server"]
