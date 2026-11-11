# AbuseIPDB Bouncer for Traefik

[![CI](https://github.com/gouglhupf/abuseipdb-bouncer-traefik-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/gouglhupf/abuseipdb-bouncer-traefik-plugin/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/gouglhupf/abuseipdb-bouncer-traefik-plugin)](https://github.com/gouglhupf/abuseipdb-bouncer-traefik-plugin/releases)
[![License](https://img.shields.io/github/license/gouglhupf/abuseipdb-bouncer-traefik-plugin)](LICENSE)
[![AI:W WRITE](https://img.shields.io/badge/AI-WRITE-grey?style=flat&logoSize=auto&labelColor=13171f)](https://0rwx.com)

A [Traefik v3](https://traefik.io/) middleware plugin that checks client IPs against [AbuseIPDB](https://www.abuseipdb.com/) and blocks abusive ones before they reach your backend. Written in pure Go using only the standard library, so it runs directly in Traefik's Yaegi interpreter — no build step, no dependencies.

## Features

- Live per-IP reputation checks (`/api/v2/check`) with a configurable `abuseConfidenceScore` threshold
- Bounded TTL/LRU cache plus singleflight: concurrent requests for the same IP share one API call
- Static allow/deny CIDRs, country allow/deny lists, and report-category filters
- Safe client-IP resolution behind trusted proxies (X-Forwarded-For, right-to-left)
- Fail-open by default; `failClosed: true` for sensitive endpoints
- Retries with `Retry-After` support and an instance-wide cooldown on rate limits
- The API key is never logged, echoed, or sent anywhere but AbuseIPDB
- Configurable decision logging (`all` / `block` / `none`)

> **Note on the AbuseIPDB blacklist:** this plugin does **not** fetch the bulk `/blacklist` snapshot. It performs cached, per-IP live checks only. If you want full blacklist coverage, apply it at the firewall level (e.g. an ipset/nftables feed built from the AbuseIPDB blacklist) — that drops packets earlier and saves API quota. The two layers complement each other well.

## Installation

Requires Traefik **v3** and an [AbuseIPDB API key](https://www.abuseipdb.com/account/api) (the free tier works).

**1. Register the plugin** in Traefik's *static* configuration:

```yaml
experimental:
  plugins:
    abuseipdb:
      moduleName: github.com/gouglhupf/abuseipdb-bouncer-traefik-plugin
      version: v0.1.0
```

**2. Define the middleware** in your *dynamic* configuration (file provider):

```yaml
http:
  middlewares:
    abuse-bouncer:
      plugin:
        abuseipdb:
          apiKey: '{{ env "ABUSEIPDB_API_KEY" }}'
          threshold: 90
```

**3. Attach it to a router:**

```yaml
http:
  routers:
    my-router:
      rule: Host(`example.com`)
      entryPoints: [websecure]
      middlewares: [abuse-bouncer]
      service: my-service
```

Set `ABUSEIPDB_API_KEY` in Traefik's environment and restart Traefik; the plugin is downloaded automatically on startup. All other settings are optional and fall back to the defaults below.

> The `{{ env "..." }}` Go-template interpolation is a Traefik **file-provider** feature. Plain `${VAR}` substitution is a Docker Compose feature and does not work in Traefik files. Keep the key out of source control and out of Docker labels / dashboard-visible configuration.

## Configuration

Traefik calls `CreateConfig()` before decoding these flat, JSON-tagged fields. Full example with defaults:

```yaml
http:
  middlewares:
    abuse-bouncer:
      plugin:
        abuseipdb:
          apiKey: REPLACE_WITH_SECRET
          threshold: 90
          maxAgeInDays: 90
          cacheTTL: 12h
          blockTTL: 1h
          errorTTL: 1m
          cacheSize: 50000
          requestTimeout: 1500ms
          maxRetries: 1
          failClosed: false
          skipPrivateRanges: true
          trustedProxies: []
          allowCIDRs: []
          denyCIDRs: []
          allowCountries: []
          denyCountries: []
          blockCategories: []
          verbose: false
          responseStatus: 403
          logDecision: all                  # all | block | none
```

Validation rules: duration strings must be positive; `cacheSize` must be positive; `threshold` is 0–100; `maxAgeInDays` 1–365; `maxRetries` 0–1; category IDs 1–23; countries two ASCII letters (case-insensitive); `responseStatus` 400–599. Invalid configuration fails middleware creation with a combined error message (never exposing the key).

### Decision order

1. Resolve `RemoteAddr`. Ignore X-Forwarded-For unless the peer belongs to `trustedProxies`; then walk the chain right-to-left until the first untrusted hop. Multiple XFF lines are supported. Invalid addresses never reach the API and use the failure policy.
2. Static allow CIDRs win over static deny CIDRs. Deny CIDRs are applied **before** private-range skipping.
3. Skip private/special-use IPv4 and IPv6 by default, including CGNAT, loopback, link-local, ULA, and documentation ranges.
4. Use the per-instance TTL/LRU result, or share one in-flight `/check` for the canonical IP.
5. Honor `isWhitelisted`, then country allow, then country deny. Otherwise block when the score is **at least** `threshold` (default 90). With `blockCategories`, score blocking additionally requires a matching report category. Category filtering automatically requests `verbose=true`; without it, verbose is omitted by default. Country allow is an exemption, not an exclusive country allowlist. Whitelist/country allow override country deny; static deny remains authoritative.
6. Cache allow decisions for `cacheTTL`, deny decisions for `blockTTL`, and API failures for `errorTTL`. On failures, allow by default or deny with `failClosed: true`.

### API behavior and lifecycle

- The API key is only sent in the `Key` header, never in a query, log, error body, or response. Redirects are rejected to avoid forwarding credentials elsewhere. Error bodies are discarded within a bound; `/check` responses are limited to 4 MiB and checked for the queried IP and a valid score.
- `requestTimeout` covers the **whole lookup**, including the response body, retry, and backoff. At most one retry is made on network errors, 5xx, or 429. Other statuses are not retried. `Retry-After` seconds and HTTP dates are honored; if the wait exceeds the remaining timeout, the lookup fails immediately and an instance-wide cooldown suppresses further calls. Invalid/missing `Retry-After` uses one minute.
- Caches, singleflight, and cooldown are per middleware instance; configuration reloads rebuild them. Multiple replicas/instances each consume their own API quota.
- Logs contain the canonical IP, verdict, source, and sanitized lookup failures — not request URLs, bodies, headers, or raw upstream errors. `logDecision` is `all` (every decision), `block` (denials only), or `none` (silent) if IP logging is unwanted.

Deploy directly in front of your backend. Keep `trustedProxies` empty unless you explicitly control the proxy chain, and remember that Traefik's own entrypoint forwarded-header policy applies before middleware execution.

## Development

Docker-only workflow: requires Docker with Compose v2 and optionally Make. No host Go installation is needed.

```sh
make test          # offline httptest unit tests
make race          # same tests with the race detector
make vet
make integration   # real Traefik v3 + Yaegi + whoami + local TLS AbuseIPDB stub
make up            # offline playground at http://localhost:8080
# / -> 200 for private/docker peers; /blocked -> 403
make down
```

Without Make, run `sh tests/integration.sh`, `docker compose up -d`, or:

```sh
docker run --rm -v "$PWD:/src" -w /src golang:1.27-bookworm go test -race ./...
```

`GO_IMAGE` overrides the unit-test/format/vet image; `TRAEFIK_PORT` overrides the host port. The integration stack has a separate Compose project and removes its containers, network, and certificate volume on exit. Its TLS stub owns the `api.abuseipdb.com` DNS alias **only inside that Docker network**, so the production HTTPS client runs unchanged without contacting AbuseIPDB or using a real key. The integration-only trust-all forwarded-header settings must never be copied into production.

`playground/dynamic.yml` is a working file-provider example; Compose mounts the plugin through Traefik's local-plugin mechanism.

## License

[Apache License 2.0](LICENSE)