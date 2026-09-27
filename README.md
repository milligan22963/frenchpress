# French Press ☕

[![CI](https://github.com/milligan22963/frenchpress/actions/workflows/ci.yml/badge.svg)](https://github.com/milligan22963/frenchpress/actions/workflows/ci.yml)

A slow-drip HTTP honeypot for unsolicited scanner traffic.

French Press listens on an HTTP port. Any request matching a configurable
list of "bad paths" — the usual scanner/exploit targets like `/wp-admin`,
`/.env`, `/xmlrpc.php` — gets held open and fed one byte at a time,
forever, instead of ever completing. Everything else passes through to your
real backend (if configured).

It's a tarpit, not a weapon: it costs the caller time, not your bandwidth,
and it never sends anything malicious. It's meant to sit in front of
whatever you're actually running and quietly waste the time of scripts that
go looking for `wp-login.php` on a server that has never run WordPress.

## What it actually does

- Matches incoming request paths against a list of known scanner targets.
- For a match, holds the connection open using HTTP chunked
  transfer-encoding and writes a one-byte chunk every 0.5–2 seconds (by
  default), and never sends the terminating chunk. A well-behaved client
  waiting for the response to finish just... waits.
- For everything else, proxies to a real backend if `-backend` is set, or
  returns a plain 404.
- Logs every brewed connection: source address, path, and how long it was
  held.

## What it does _not_ do

- It does not stop a sophisticated, patient attacker. Anything with a
  reasonable client timeout will eventually give up — the win here is
  against sloppy, high-volume scanning scripts, not targeted intrusion
  attempts.
- It is not a substitute for a real WAF, firewall, or IDS.
- It does not send anything harmful back to the caller. No zip bombs, no
  exploit payloads — just very, very slow, very boring bytes.

## Quick start

Prebuilt Linux binaries for `amd64` and `arm64` are on the
[releases page](https://github.com/milligan22963/frenchpress/releases),
each with a `checksums.txt`. Or build from source:

```bash
go build -o frenchpress ./cmd/frenchpress
./frenchpress -addr :8080 -backend http://127.0.0.1:3000
```

Point your reverse proxy (nginx, Caddy, Traefik) at French Press for the
paths you want tarpitted, and let everything else go straight to your real
site. See [`configs/nginx.example.conf`](configs/nginx.example.conf) for a
starting point.

Or run it standalone with no backend — anything not on the bad-path list
just gets a 404.

## Running as a shim on port 80

French Press can sit directly on port 80 in front of your real site:
requests to bad paths get tarpitted, and everything else is proxied to
`-backend` unchanged. The proxy passes the original `Host` header through,
adds `X-Forwarded-For`, and supports WebSocket upgrades and server-sent
events.

```bash
go build -o frenchpress ./cmd/frenchpress
# Binding :80 needs privilege; grant just that capability instead of running
# as root. Re-run after every rebuild — a new binary loses the capability.
sudo setcap cap_net_bind_service=+ep ./frenchpress
./frenchpress -addr :80 -backend http://127.0.0.1:3000
```

Or with [Task](https://taskfile.dev), which builds, applies the capability,
and starts the shim:

```bash
task shim                                   # :80 -> http://127.0.0.1:3000
task shim BACKEND=http://127.0.0.1:9000     # different backend
```

Under systemd, use `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit
instead of `setcap`.

### HTTPS on port 443

French Press can terminate TLS itself, either from certificate files or
with automatic [Let's Encrypt](https://letsencrypt.org) certificates. Add
`-redirect-addr :80` to also listen on plain HTTP: bad paths there are
still tarpitted, and everything else gets a `301` to HTTPS.

```bash
# Your own certificate (PEM files)
./frenchpress -addr :443 -redirect-addr :80 \
  -tls-cert /etc/ssl/example.com.crt -tls-key /etc/ssl/example.com.key \
  -backend http://127.0.0.1:3000

# Let's Encrypt, fetched and renewed automatically
./frenchpress -addr :443 -redirect-addr :80 \
  -autocert example.com,www.example.com -autocert-email you@example.com \
  -autocert-cache /var/lib/frenchpress/autocert \
  -backend http://127.0.0.1:3000
```

Or with Task:

```bash
task shim-tls TLS_CERT=/etc/ssl/example.com.crt TLS_KEY=/etc/ssl/example.com.key
task shim-autocert DOMAINS=example.com,www.example.com EMAIL=you@example.com
```

Notes:

- `-autocert` needs the named hosts' DNS pointed at this machine and ports
  80 and/or 443 reachable from the internet, so Let's Encrypt can validate.
  Keep `-autocert-cache` on persistent storage: losing it means reissuing,
  and Let's Encrypt rate-limits that.
- HTTPS is served with TLS 1.2 minimum, and HTTP/2 is negotiated
  automatically. Bad paths are tarpitted over HTTP/1.1 and HTTP/2 alike.
- Proxied requests get `X-Forwarded-Proto` and `X-Forwarded-Host` set from
  the client's connection to French Press, overwriting whatever the client
  sent. If French Press sits behind another proxy of yours that sets them,
  pass `-trust-forwarded` to keep them.
- Request headers must arrive within `-read-header-timeout` (default
  `10s`), which protects proxied traffic from slowloris-style clients. It
  doesn't affect the slow drip, which is on the response side.

Limitations to be aware of when French Press is your front door:

- Only one backend; no host- or path-based routing to multiple upstreams.
- Backend failures return a bare `502 Bad Gateway`.

## Configuring bad paths

By default, French Press uses a small built-in list of common scanner
targets (see `internal/paths/paths.go`). You can supply your own list via a
YAML file:

```bash
./frenchpress -bad-paths configs/badpaths.example.yaml
```

```yaml
# configs/badpaths.example.yaml
include_defaults: true # merge with the built-in list; defaults to true

paths:
  - /old-admin-panel
  - /backup.sql
  - /.htpasswd
```

- If `-bad-paths` is omitted, the built-in defaults are used on their own.
- If `-bad-paths` is given and `include_defaults` is unset or `true`, your
  list is merged with the built-in defaults (deduplicated).
- If `include_defaults: false` is set in the file, only your list is used.
- The `-include-defaults` CLI flag, **if explicitly passed**, overrides
  whatever the YAML file says — useful for scripted/CI overrides without
  editing the file.

```bash
# Force defaults on even if the YAML file says include_defaults: false
./frenchpress -bad-paths configs/badpaths.example.yaml -include-defaults=true
```

## CLI flags

| Flag                | Default   | Description                                                               |
| ------------------- | --------- | ------------------------------------------------------------------------- |
| `-addr`             | `:8080`   | Address to listen on                                                      |
| `-bad-paths`        | _(empty)_ | YAML file of bad paths; built-in defaults used if omitted                 |
| `-backend`          | _(empty)_ | Real backend URL to proxy non-bad-path requests to; 404 if omitted        |
| `-min-delay`        | `500ms`   | Minimum delay between drip bytes                                          |
| `-max-delay`        | `2s`      | Maximum delay between drip bytes                                          |
| `-max-brew-time`    | `10m`     | Hard cap on how long a single connection is held open                     |
| `-max-concurrent`   | `500`     | Max connections brewing at once — protects _your_ resources under a flood |
| `-include-defaults` | `true`    | Include built-in bad paths alongside `-bad-paths` file (overrides file)   |
| `-log-config`       | _(empty)_ | [pflog](https://github.com/PageFaultCode/pflog) YAML file; text to stdout if omitted |
| `-tls-cert`         | _(empty)_ | PEM certificate; with `-tls-key`, serves HTTPS on `-addr`                 |
| `-tls-key`          | _(empty)_ | PEM private key for `-tls-cert`                                           |
| `-autocert`         | _(empty)_ | Comma-separated hostnames to get Let's Encrypt certificates for           |
| `-autocert-cache`   | `autocert-cache` | Directory `-autocert` stores certificates in                       |
| `-autocert-email`   | _(empty)_ | Contact email registered with Let's Encrypt (optional)                    |
| `-redirect-addr`    | _(empty)_ | With TLS on, plain-HTTP listener: tarpits bad paths, redirects the rest   |
| `-trust-forwarded`  | `false`   | Keep incoming `X-Forwarded-Proto`/`-Host` instead of overwriting them      |
| `-read-header-timeout` | `10s`  | Time allowed to read request headers                                      |
| `-version`          | `false`   | Print the version and exit                                                |

## Logging

Logging goes through [pflog](https://github.com/PageFaultCode/pflog). With
no `-log-config`, French Press logs text to stdout at `Information`. To
change level, add file output or rotation, pass a pflog configuration file:

```bash
./frenchpress -log-config configs/log.example.yaml
```

```yaml
# configs/log.example.yaml
settings:
  level: Information
  trigger_level: Error # at or above this, the whole backlog is dumped
  backlog: 500
formatters:
  - id: text
    filename: stdout
  - id: json # JSON Lines, one record per line
    filename: "/var/log/frenchpress.json"
    max_size_mb: 10
    max_backups: 5
    compress: true
```

Each brewed connection logs a start line (method, path, source) and an end
line with how long it was held and why it ended. Connections still brewing
when the process exits get no end line.

`kill -USR1 <pid>` dumps the in-memory backlog on demand.

## Deployment notes

- **Put it behind a real reverse proxy.** Route only known-bad paths to
  French Press; let real traffic go straight to your actual site. French
  Press's own `-backend` proxying is there for simple setups, but a
  dedicated proxy (nginx/Caddy/Traefik) gives you more control over TLS,
  routing, and rate limiting.
- **Set `-max-concurrent` sanely.** This is what stops a large scan flood
  from pinning your own resources — you're trying to cost _them_ time,
  not yourself.
- **Don't chain it with anything that amplifies traffic** (a CDN, a shared
  host with strict resource limits, a corporate WAF you don't control).
  Keep the tarpit fully inside infrastructure you own.
- **Logs are your dataset.** Every brewed connection is logged with source,
  path, and duration — that's the fun part.

## CI and releases

Every push to `main` and every pull request runs `gofmt`, `go vet`,
`go test -race` and a build against both the `go.mod` Go version and the
latest stable Go, plus [govulncheck](https://go.dev/doc/security/vuln/).

Pushing a `v*` tag builds static Linux `amd64` and `arm64` binaries and
publishes them as a GitHub release with generated notes:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Contributing

PRs welcome — this started as a "wouldn't it be funny if" idea, so
extensions, better logging/metrics, a Prometheus endpoint, an
allow-list mode, whatever. Keep the core philosophy: waste their time,
never send anything actually harmful, and never risk taking out
infrastructure you don't own.

## License

MIT — see [LICENSE](LICENSE).
