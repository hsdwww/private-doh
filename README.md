# private-doh

A minimal, self-contained **DoH (DNS-over-HTTPS) gateway** in Go with ad filtering, ECS passthrough and hot-reloadable blocklists.

```
clients (browser DoH, RFC 8484)
  → Go TLS listener (your cert, e.g. Let's Encrypt DNS-01)
    → HaGeZi Light blocklist filtering (~39k domains, daily auto-update, hot reload)
    → local empty answer for HTTPS/type65 RR (prevents ECH from breaking domain-based routing)
    → dynamic ECS /24 injection (real client subnet preserved, RFC 7871)
    → TTL in-memory cache (ECS-partitioned)
    → Google DoH primary / Quad9 secondary (pinned dial IPs, bootstrap-independent)
```

## Features

- **Single static binary, single config file** — no cgo, no external services
- Token-protected DoH endpoint (`/dns/<token>`), GET + POST, per-IP rate limiting
- Ad filtering with daily rule updates, crash-safe atomic version rotation (current/previous symlinks, automatic pruning to last 2 versions), hot reload without restart
- Dynamic ECS injection + ECS-partitioned cache
- Local empty answer for type65/HTTPS records — keeps ECH config records from breaking sing-box/domain-based routing
- Pinned upstream dial IPs — immune to proxy env vars and bootstrap loops
- systemd unit set: sandboxed service, resource slice, daily rules/cert timers
- 61 unit tests incl. `-race`, with mutation-tested regression suites for the rotation logic

## Quick start

Requirements: Go 1.25+, a domain with DNS hosted on Cloudflare (for DNS-01), ports 8443/tcp open.

```bash
# 1. build
cd src && go build -trimpath -o ../private-doh ./cmd/private-doh

# 2. generate a token and write /etc/private-doh/config.json (see config/config.example.json)
./private-doh gen-token

# 3. install systemd units from systemd/ (adjust paths/users to your distro)
# 4. point your browser at:
#    https://<your-domain>:8443/dns/<token>
```

## Configuration

Copy `config/*.example` to `/etc/private-doh/` and edit:

- `config.json` — listener, token (≥32 chars), upstreams with pinned IPs
- `rules-update.json` — blocklist source URL, sanity limits (min/max entries, max delta %), protected domains (never pruned/filtered)
- `acme.env` — `ACME_EMAIL` for the Let's Encrypt account (consumed by `systemd/cert-renew.sh`)
- `allowlist.txt` — per-domain overrides; hot-reloads within ~2 min

## Operations

```bash
systemctl status private-doh
curl -s --unix-socket /run/private-doh/admin.sock http://localhost/stats
# why is a domain blocked/allowed?
./private-doh explain --name ads.example.com --rules /var/lib/private-doh-rules --allowlist /etc/private-doh/allowlist.txt
# manual rule refresh (keeps old version on failure)
systemctl start private-doh-rules-update.service
```

## Credits / Third-party

This project is original code, but stands on the following:

- **[HaGeZi dns-blocklists](https://github.com/hagezi/dns-blocklists)** (GPL-3.0) — ad-block filter data. Downloaded at runtime directly from upstream; **this project does not distribute the lists** — your deployment fetches them under the upstream license terms.
- **[miekg/dns](https://github.com/miekg/dns)** (BSD-3-Clause) — DNS message library.
- **[golang.org/x/sync](https://pkg.go.dev/golang.org/x/sync)** (BSD-3-Clause) — singleflight.
- **[lego](https://github.com/go-acme/lego)** (MIT) — ACME client used by the cert renewal script.
- DNS-over-HTTPS per RFC 8484, ECS per RFC 7871, HTTPS RR per RFC 9460.

## License

MIT — see [LICENSE](LICENSE). Third-party components keep their own licenses (see Credits).

## Status

Personal infrastructure project; published as-is. Docs and deploy tooling are minimal — read the source and units before running.
