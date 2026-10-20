# Banner Fingerprint System

A banner-fingerprint identification service written in Go.  
Given a batch of raw network-scan records (IP, port, banner string) it returns
the identified protocol, software product, version, OS hint, and confidence score.

## Quick start

```bash
# One command — builds both images and runs client against data/input.json
docker compose up --build
```

The client prints a tabular result and a JSON block, then exits.  
The server keeps running and can accept further requests.

## Architecture

```
┌──────────────────────────────────────────┐
│  Docker Compose (isolated bridge network) │
│                                           │
│   ┌──────────────┐    POST /fingerprint   │
│   │   client     │ ──────────────────────▶│
│   │  (one-shot)  │                        │
│   └──────────────┘   ┌──────────────────┐ │
│                       │     server       │ │
│                       │  :8080 (internal)│ │
│                       └──────────────────┘ │
└──────────────────────────────────────────┘
```

- **server** — HTTP API; builds from `scratch`, runs as UID 10001, read-only root FS.
- **client** — reads `data/input.json`, POSTs to the server, prints results.
- **Network** — `internal: true`; containers are invisible to the public internet at runtime.
- **Health check** — the server binary handles `-health-check` itself (no shell/curl needed in scratch).
- **Dependency** — Compose waits for `service_healthy` before starting the client.

## API

### `POST /fingerprint`

**Request**

```json
{
  "targets": [
    { "ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" }
  ]
}
```

**Response**

```json
{
  "results": [
    {
      "ip": "1.2.3.4",
      "port": 22,
      "protocol": "SSH",
      "product": "OpenSSH",
      "version": "8.9p1",
      "os_hint": "Ubuntu-3",
      "confidence": 0.95
    }
  ]
}
```

Unrecognised banners return `"protocol": "unknown"` with a port-based fallback
confidence of 0.4 when the port is well-known, or 0 otherwise.  
The server **never crashes** on bad input — every record gets a result.

### `GET /health`

Returns `{"status":"ok"}` with HTTP 200 when the server is ready.

## Recognised protocols (built-in rules)

| Protocol | Products |
|----------|----------|
| SSH | OpenSSH (Ubuntu, Debian, generic) |
| HTTP | nginx, Apache, Jetty, IIS, lighttpd, Caddy, Tomcat, Elasticsearch |
| MySQL | MySQL 5.x / 8.x |
| Redis | PONG, ERR, NOAUTH, WRONGPASS banners |
| FTP | ProFTPD, vsFTPd, Pure-FTPd, FileZilla |
| SMTP | Postfix, Exim, Sendmail |
| PostgreSQL | generic |
| MongoDB | generic |
| TLS | handshake detection |
| RDP | handshake detection |
| Memcached | generic |
| VNC | RFB version |
| Telnet | IAC detection |

## Rule file

Rules live in `server/rules/fingerprints.yaml` — **fully decoupled from the binary**.  
Add, edit, or remove rules without recompiling; only a container rebuild is needed
to pick up changes (the file is baked into the image at build time).

Each rule has:

```yaml
- name: openssh_ubuntu
  protocol: SSH
  product: OpenSSH
  patterns:
    - "SSH-[\\d.]+-OpenSSH_([\\d.p]+)\\s+Ubuntu"
  version_pattern: "SSH-[\\d.]+-OpenSSH_([\\d.p]+)"
  os_pattern:      "SSH-[\\d.]+-OpenSSH_[\\d.p]+\\s+(Ubuntu[^\\s]*)"
  confidence: 0.95
```

Rules are evaluated in order; the first match wins.

## Custom input

Replace `data/input.json` with any array of `{ip, port, banner}` objects, then:

```bash
docker compose up --build
```

Or send directly to the server if it is already running:

```bash
curl -s -X POST http://localhost:8080/fingerprint \
  -H 'Content-Type: application/json' \
  -d '{"targets":[{"ip":"10.0.0.1","port":22,"banner":"SSH-2.0-OpenSSH_9.3"}]}'
```

(Expose port 8080 in `docker-compose.yml` first: add `ports: ["8080:8080"]` under `server`.)

## Project layout

```
banner-fingerprint/
├── server/
│   ├── main.go                        # HTTP handlers + health-check mode
│   ├── go.mod
│   ├── Dockerfile                     # multi-stage, scratch runtime
│   ├── internal/
│   │   ├── engine/engine.go           # fingerprint engine (YAML rules → regex)
│   │   └── models/models.go           # shared request/response types
│   └── rules/
│       └── fingerprints.yaml          # ← edit rules here, no recompile needed
├── client/
│   ├── main.go                        # reads JSON, POSTs, prints table + JSON
│   ├── go.mod
│   └── Dockerfile                     # multi-stage, scratch runtime
├── data/
│   └── input.json                     # sample input (replace for custom runs)
└── docker-compose.yml
```
