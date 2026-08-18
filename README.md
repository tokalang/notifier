# notifier

An official standalone application deliverable for Toka providing controlled outbound HTTP/TLS delivery and webhook notification orchestration.

## Features

- **Standard RC6 Network Stack**: Direct, robust network execution using Toka's native `stdx/net/http`, `stdx/net/url`, `stdx/net/tls`, and `std/net` modules.
- **Strict Outbound Security**: Enforces `https://` by default. Plain `http://` is strictly limited to exact loopback addresses (`127.0.0.1` and `localhost`). Plain public `http://` requires an explicit `--allow-insecure-http` override.
- **Raw-Byte Idempotency Key**: Validates that event payloads are valid JSON, and computes the `Idempotency-Key` SHA-256 header directly over the un-reserialized raw payload bytes.
- **Controlled Retries & Status Discrimination**:
  - `2xx`: Delivery success (exit code 0).
  - `3xx` (Redirects): Non-retryable failure (no automatic redirects to prevent SSRF, exit code 1).
  - `4xx` (Client Errors, including `429`): Non-retryable failure, aborts immediately without retry (exit code 1).
  - `5xx` & Network Failures: Retryable with backoff up to `max_retries` additional attempts.
- **Reserved System Header Protection**: Custom headers cannot override system-enforced headers (`Host`, `Content-Length`, `Content-Type`, `Idempotency-Key`, `User-Agent`, `Connection`).
- **Dry-Run Inspection**: `--dry-run` simulates request generation and outputs formatted, redacted wire frames without performing network I/O.
- **IPv4 DNS Support**: Resolves hostnames via IPv4 DNS (`resolve_ipv4`).

## Installation & Consumption

In your Toka project manifest (`package.tk`):

```toka
dependencies = (
    notifier = "notifier:0.1.0",
)
```

## CLI Usage

```bash
# Display help and version
notifier --help
notifier --version

# Send an event JSON to a webhook endpoint
notifier --config config.yaml --event event.json send

# Dry-run inspection (does not perform network requests)
notifier --config config.yaml --event event.json --dry-run send

# Override security policy to allow plain public HTTP
notifier --config config.yaml --event event.json --allow-insecure-http send
```

## Configuration (`config.yaml`)

```yaml
endpoint: "https://api.example.com/webhook"
timeout_ms: 5000         # Connect and read timeout in ms (default: 5000)
max_retries: 3           # Extra retry attempts (default: 3)
backoff_ms: 100          # Base backoff in ms (default: 100)
ca_file: ""              # Optional custom CA certificate file path
allow_insecure_http: false
headers:
  Authorization: "Bearer your-secret-token"
  X-Custom-Header: "my-service"
```
