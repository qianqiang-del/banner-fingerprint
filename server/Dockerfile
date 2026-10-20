# syntax=docker/dockerfile:1.6
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install CA certs for the runtime copy
RUN apk add --no-cache ca-certificates

# Copy module descriptor first; source follows so cache invalidation
# only happens when source changes, not just go.mod.
COPY go.mod ./
COPY . .

# go mod tidy regenerates go.sum from the module graph — no pre-committed
# go.sum required; build remains hermetic inside the image layer cache.
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /server .

# ── Runtime image (distroless-style using scratch) ─────────────────────────
FROM scratch

# TLS roots needed if the server ever calls outbound HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# The statically linked binary and the decoupled rule file
COPY --from=builder /server /server
COPY rules/ /app/rules/

# Drop to a non-root UID/GID; scratch images accept numeric IDs directly
USER 10001:10001

EXPOSE 8080

ENV RULES_PATH=/app/rules/fingerprints.yaml

# CMD form (no shell needed) works perfectly in scratch images because
# Docker daemon executes the binary directly inside the container filesystem.
ENTRYPOINT ["/server"]
