# Contributing to French Press

Thanks for poking around. This is a fun, low-stakes project — a honeypot
tarpit, not production security infrastructure — so contributions in that
spirit are welcome.

## Ground rules

1. **Cost them time, not us.** Any change should keep the core property
   that French Press protects its own resources (connection caps, timeouts)
   at least as well as the current code.
2. **Never send anything actually harmful.** No exploit payloads, no zip
   bombs, no amplification tricks that could hurt infrastructure the
   caller doesn't control. Slow and boring is the whole point.
3. **Keep it dependency-light.** Currently the only external dependency is
   `gopkg.in/yaml.v3`. Adding more should have a clear justification.

## Getting started

```bash
git clone <your-fork-url>
cd french-press
go build ./...
go test ./...
```

## Ideas that would be welcome

- Prometheus metrics (connections brewing, total brew-time served, hits per
  path)
- An allow-list mode (only tarpit these paths, ignore everything else,
  rather than proxy/404)
- A Dockerfile / docker-compose example
- Raw TCP listener wiring in `cmd/frenchpress` for non-HTTP ports (the
  `tarpit.BrewRaw` function already exists but isn't wired into main yet)
- Better structured logging (JSON logs, per-IP hit counts)

## Pull requests

Small, focused PRs are easiest to review. Please include a one-line
description of what scanner behavior you're targeting or what you're
fixing, and run `go test ./...` before submitting.
