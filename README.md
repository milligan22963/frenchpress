# French Press ☕

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

## Contributing

PRs welcome — this started as a "wouldn't it be funny if" idea, so
extensions, better logging/metrics, a Prometheus endpoint, an
allow-list mode, whatever. Keep the core philosophy: waste their time,
never send anything actually harmful, and never risk taking out
infrastructure you don't own. Will see about incoporating pflog from my other repo set for logging.

## License

MIT — see [LICENSE](LICENSE).
