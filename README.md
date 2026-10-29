# Zero-Trust Web Proxy

A forward web proxy written in Go (standard library only) that applies **zero-trust access control** to outbound web traffic. Every request must prove who it comes from, is checked against that user's group policy, and is logged — nothing is allowed just because it came from inside the network.

It is a small-scale model of a Secure Web Gateway, the kind of product cloud security platforms run at scale.

## Features

- **Identity on every request** — users authenticate with `Proxy-Authorization: Basic`; passwords are stored salted and hashed, compared in constant time, and never forwarded upstream.
- **Policy engine** — per-group, ordered, first-match rules on destination domain (with `*.wildcards`), URL category and file extension. Unknown groups and unmatched traffic fall to a default action (deny by default for staff groups).
- **HTTP and HTTPS** — plain HTTP is relayed with hop-by-hop headers stripped (RFC 7230); HTTPS uses `CONNECT` tunnelling, so traffic stays end-to-end encrypted and policy is applied to the destination host.
- **Per-user rate limiting** — token-bucket limiter.
- **Structured access logs** — one JSON line per request (user, group, host, path, decision, matched rule, category, status, bytes, latency), ready for a SIEM or log pipeline.
- **Observability** — Prometheus-style counters on `/metrics` and a `/healthz` check, on a separate admin port bound to localhost by default.
- **Graceful shutdown**, distroless non-root container image, CI with `gofmt`, `go vet` and race-detector tests.

## How a request is handled

```
client ──► authenticate ──► rate limit ──► policy decision ──► forward / tunnel
              │ 407            │ 429            │ 403
              └────────────────┴────────────────┴──► JSON access log (every request)
```

## Quick start

```bash
go run ./cmd/ztproxy                     # proxy on :8080, admin on 127.0.0.1:9090

# demo users (password "changeme"): alice=engineering, bob=finance, guest1=guest
curl -x http://alice:changeme@localhost:8080 https://github.com      # allowed (dev-tools)
curl -x http://alice:changeme@localhost:8080 http://news.example/    # 403 default deny
curl -x http://alice:changeme@localhost:8080 http://evil.test/       # 403 malware category
curl -x http://localhost:8080 http://example.com/                    # 407 no credentials
curl localhost:9090/metrics
```

Add a user: `go run ./cmd/ztproxy -hash 'their-password'` prints a salt and hash to paste into `configs/users.json`.

### Docker

```bash
docker build -t ztproxy .
docker run -p 8080:8080 ztproxy
```

## Policy file

```json
"engineering": {
  "default_action": "block",
  "rules": [
    { "name": "block-malware",     "action": "block", "categories": ["malware"] },
    { "name": "block-executables", "action": "block", "extensions": [".exe", ".msi"] },
    { "name": "allow-dev-tools",   "action": "allow", "categories": ["dev-tools"] }
  ]
}
```

Rules are evaluated top to bottom and the first match wins, so block rules go before broad allow rules. The policy is validated at start-up: unknown actions or categories stop the proxy instead of failing open.

## Sample log line

```json
{"ts":"2026-10-29T11:56:45Z","client_ip":"10.0.0.7","user":"alice","group":"engineering","method":"GET","host":"evil.test","path":"/x","action":"block","rule":"block-malware","category":"malware","status":403,"bytes_out":0,"duration_ms":0}
```

These logs are the input format for the companion project, [security-log-pipeline](https://github.com/arxan99/security-log-pipeline).

## Project layout

```
cmd/ztproxy/          entry point, flags, servers, graceful shutdown
internal/auth/        credential store and Basic-auth verification
internal/policy/      categories, rules and decision engine
internal/proxy/       HTTP forwarding, CONNECT tunnelling, logging, metrics
internal/ratelimit/   token-bucket limiter
configs/              sample policy and users
```

## Tests

```bash
go test -race -cover ./...
```

Tests cover domain matching, rule ordering, default deny, config validation, authentication failures, rate limiting, and end-to-end forwarding and CONNECT tunnelling through a live test server.

## Limitations and next steps

- HTTPS is filtered by hostname only; there is no TLS interception, so paths inside HTTPS are not inspected.
- SHA-256 is used for password hashing to stay dependency-free; a production system should use bcrypt or Argon2.
- Category lists are static; a real gateway would query a threat-intelligence feed.
- Ideas: hot-reload policy on change, SNI-based checks, DNS-level blocking, mTLS device posture checks.
