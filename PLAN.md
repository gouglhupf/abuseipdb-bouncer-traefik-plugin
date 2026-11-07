# abuseipdb-traefik-bouncer — Plan

Middleware plugin for Traefik v3 that decides, per request, whether the client IP may be
forwarded to the backend, based on AbuseIPDB.

## 1. Decisions at a glance

| Topic | Choice | Why |
|---|---|---|
| Plugin system | **Go + Yaegi** (interpreted, `plugins.traefik.io/create`) | Catalog-listable, no compile step/toolchain, `net/http` + `encoding/json` + `sync` + `time` available. |
| Dependencies | **Zero** (stdlib only) | Vendoring requirement in the catalog; hand-roll LRU + singleflight + token bucket |
| Primary decision source | **Bulk `/api/v2/blacklist` snapshot** in memory (background refresher) | Free tier = only **5 blacklist calls/day** but gives instant, offline O(1) decisions for ~10k IPs. Zero per-request latency. |
| Secondary decision source | **Live `/api/v2/check`** on cache miss | Per-IP detail (`abuseConfidenceScore`).  |
| Default failure mode | **fail-open** (allow on API error), configurable | Availability first for an HTTP front door; `failClosed: true` for admin/SSH-over-HTTP endpoints. |
| Verdict signal | `abuseConfidenceScore >= threshold` (default **90**), honour `isWhitelisted`, optional category/country filters | AbuseIPDB docs explicitly recommend the score over `isWhitelisted`, and 75–100 as the sane blocking range. |
| Verdict on block | `403` + `X-AbuseIPDB-*` diagnostics headers, no key/PII echo | Debuggable without leaking secrets. |

Note: the JSON in the task description (pagination + `results`) is the **`/reports`** shape.
`/check` returns a single `data` object (`ipAddress`, `abuseConfidenceScore`, `isWhitelisted`,
`totalReports`, `reports[]` when `verbose`). Plan parses the real `/check` shape, and we
**omit `verbose`** by default (payload weight) behind a `verbose: false` option.

## 2. Request path (hot path, must stay in µs)

```
request
  ├─ 1. resolve client IP (req.RemoteAddr, then XFF chain right→left, stop at first untrusted hop)
  ├─ 2. static allow (own CIDRs) / deny CIDRs            → decide, no network
  ├─ 3. skip non-public IPs (loopback, RFC1918, ULA, CGNAT) → allow, no network
  ├─ 4. blacklist snapshot map lookup (conf >= minConfidence) → block, no network
  ├─ 5. LRU cache hit (allow OR deny, TTL)               → decide, no network
  ├─ 6. singleflight live /check (timeout, 1 retry, honour Retry-After on 429)
  ├─ 7. policy engine → allow / deny; store in LRU (positive + negative TTL)
  └─ 8. allow → next.ServeHTTP   |   deny → 403
```

Key properties:
- **Never one API call per request.** Cache.
- **Concurrent requests to the same uncached IP = 1 API call** (singleflight).
- Negative caching with its own TTL, plus a shorter "error" TTL so we retry eventually.
- Snapshot refresher runs in a goroutine tied to the `ctx` passed to `New()`; stale snapshot
  is kept if a refresh fails (serve-stale-then-error, never blank).
- All state guarded by `sync.RWMutex`; no blocking I/O while holding a write lock.

## 3. Configuration schema (draft)

```yaml
# dynamic
http:
  middlewares:
    abuse-bouncer:
      plugin:
        abuseipdb:
          apiKey: "${ABUSEIPDB_API_KEY}"   # env expansion works with the file provider
          threshold: 90                    # block when abuseConfidenceScore >= threshold
          maxAgeInDays: 90                 # 1..365
          verbose: false                   # include reports[] in /check (heavier payload)
          useBlacklist: true               # bulk snapshot
          blacklistMinConfidence: 90       # confidenceMinimum for the snapshot
          blacklistInterval: 6h            # >= 15m; free tier allows only 5 calls/day
          blacklistLimit: 10000            # subscription cap silently truncates
          cacheTTL: 12h                    # positive (allow) results
          blockTTL: 1h                     # negative (deny) results
          errorTTL: 1m                     # failed lookups (retry window)
          cacheSize: 50000                 # LRU entries
          requestTimeout: 1500ms
          maxRetries: 1
          failClosed: false                # deny vs allow when AbuseIPDB is unusable
          allowCIDRs: ["203.0.113.0/24"]   # office/VPN always pass
          denyCIDRs: []                    # instant block, no network
          skipPrivateRanges: true
          trustedProxies: []               # if empty: XFF is ignored (spoof-safe default)
          blockCategories: []              # empty = any category counts
          allowCountries: []               # empty = any
          denyCountries: []
          responseStatus: 403
          logDecision: true
```

Static config:

```yaml
experimental:
  plugins:
    abuseipdb:
      moduleName: github.com/<you>/abuseipdb-traefik-bouncer
      version: v0.1.0
```

`Config` stays flat, JSON-tagged, data-only (no interfaces/pointers), so Traefik can
decode it from YAML/labels/CRD; `Validate()` returns aggregated errors and `New()` refuses
to start with an empty `apiKey` (or `useBlacklist`/`check` disabled + no key).

## 5. API layer

- `GET https://api.abuseipdb.com/api/v2/check?ipAddress=<urlencoded>&maxAgeInDays=N`
- `GET https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=N&limit=N` (plaintext accept)
- Headers: `Key`, `Accept: application/json` (JSON errors, not HTML), `User-Agent` set.
- URL-encode the IP (IPv6 colons), never put the key in the query string.
- Treat **HTTP status** as truth: 200 ok, 400/422 config error (fail fast at startup on 422),
  403 bad key, 402 plan limit, 429 rate limited → back off using `Retry-After`,
  5xx → retry once, then fallback policy.
- Shared `http.Transport` with `MaxIdleConnsPerHost`, `ForceAttemptHTTP2`, TLS defaults.
- Response body read with `io.LimitReader` (blacklist can be ~500k lines).

## 6. Security & privacy

- API key: only in the request header; never logged, never in `X-AbuseIPDB-*` headers,
  never in error strings. Recommend file provider + `${ENV}` expansion or K8s secret → env
  (Docker labels and the dashboard expose literal values).
- X-Forwarded-For is trusted **only** for `trustedProxies`; otherwise `RemoteAddr` only
  (otherwise the bouncer is bypassable by header spoofing).
- Default `skipPrivateRanges: true` so internal traffic never leaks client IPs to a third party.
- Only the queried IP + decision go to logs; no request body/URL/user-agent (GDPR-friendly).
- Plugin does not read or modify the request body; purely a gate.

## 7. Testing plan

- **Unit** (all offline, `httptest.Server`): `/check` parse fixtures (clean, score 100,
  whitelisted, IPv6), `/blacklist` parse, `Retry-After`/429, 500, timeout,
  stale-snapshot serving, config validation matrix, XFF chain incl. spoofing, CIDR allow.
- **Race**: `go test -race` with concurrent identical + distinct IPs (asserts singleflight:
  1 upstream call per IP).
- **Integration**: `docker-compose.yml` running Traefik `v3` + `whoami`, plugin loaded via
  `--experimental.localPlugins.abuseipdb moduleName=...` from `./plugins-local/src/...`,
  plus a `toxiproxy`-ish stub to force timeouts/429. Script asserts 200/403 + headers.
- **Lint**: `.golangci.yml` (traefik plugin style: exhaustive, godoc on exported, `go vet`).


## 8. Yaegi constraints we must respect (design drivers)

- Interpreted Go: avoid generics, avoid `reflect`/`unsafe`, no CGO, no `os/exec`.
- No Traefik logger injection → logging only via `os.Stdout`/`os.Stderr` string writes.
- No plugin lifecycle hooks beyond the `ctx` given to `New()`: background refresher must exit
  on `ctx.Done()`; no cleanup possible after unload (keep goroutine count at 1).
- Plugin code cannot share state between middleware instances → cache is per-instance
  (documented; use bulk blacklist mode on multi-replica setups so each replica is cheap).
- Config reload creates a new instance → caches are rebuilt; keep warmup cheap.

## 9. Roadmap

| Milestone | Deliverable |
|---|---|
| M0 | Repo skeleton, manifest, Makefile, docker-compose local playground (plugin logs "hello") |
| M1 | Config + validation + IP resolution + static CIDR allow/deny, unit tests |
| M2 | `/check` client, LRU + singleflight, policy engine, fail-open/closed, tests |
| M3 | `/blacklist` snapshot refresher + atomic swap + stale serving, `useBlacklist` path |
| M4 | Docs, lint/CI clean, tagged release, catalog listing |

### Implementation status (M0–M2)

- [x] M0: stdlib-only module, Traefik manifest/entrypoints, Docker Make targets, local Compose playground with startup greeting.
- [x] M1: flat configuration/defaults, aggregated validation, spoof-safe IP/XFF resolution, public-range handling, static CIDR allow/deny, unit tests.
- [x] M2: bounded `/check` client, retry/Retry-After cooldown, TTL LRU and per-IP singleflight, policy engine, diagnostics, fail-open/closed, offline and race tests.
- [x] Actual Traefik v3/Yaegi integration against a Docker-local TLS stub (no real key/API calls).
- [ ] M3: blacklist snapshot/refresher. Until then `useBlacklist` retains the draft default but uses live checks; examples explicitly disable it.
- [ ] M4: release/catalog, CI/lint, final documentation.

Implementation clarifications: New does no API I/O, so HTTP 422 cannot fail startup; local validation rejects invalid configuration and upstream errors use the failure policy. Category filters automatically enable verbose reports. A provider-wide 429 cooldown is implemented; a configurable daily quota/token-bucket limiter is not. The module path uses `your-org` until the publishing repository is known. See README.md for configuration semantics and Docker-only test commands. File-provider environment expansion uses Traefik Go templates, not bare `${ENV}` as suggested in the draft above.

## 11. Questions

1. Is there a CDN/LB in front? -> proxys in front traefik are out of scope
