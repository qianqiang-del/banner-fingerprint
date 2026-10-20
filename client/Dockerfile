# syntax=docker/dockerfile:1.6
FROM golang:1.21-alpine AS builder

WORKDIR /build

COPY go.mod ./
COPY . .

RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /client .

# ── Runtime image ──────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /client /client

USER 10001:10001

VOLUME ["/data"]

ENTRYPOINT ["/client"]
