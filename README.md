# AbuseIPDB Traefik bouncer

Stdlib-only Go/Yaegi middleware for Traefik v3. Features available: configuration validation, safe client-IP resolution, static CIDRs, live `/check`, policy evaluation, bounded TTL/LRU caching, and per-IP singleflight.

The module path `github.com/your-org/abuseipdb-traefik-bouncer` is a placeholder. Before publishing, update it consistently in `go.mod`, `.traefik.yml`, `compose.yml`, and `tests/compose.yml`. The package name matches Traefik's underscore-normalized module basename.

## Docker-only development

Requires Docker with Compose v2 and optionally Make. No host Go installation or package installation is needed; Docker pulls the referenced images as necessary.

```sh
make test          # offline httptest unit tests
make race          # same tests with the race detector, CGO supplied by the image
make vet
make integration   # actual Traefik v3 + Yaegi + whoami + local TLS AbuseIPDB stub
make up            # offline playground at http://localhost:8080
# / -> 200 for private/docker peers; /blocked -> 403 with diagnostic headers
make down
```

Without Make, run `sh tests/integration.sh`, `docker compose up -d`, or:

```sh
docker run --rm -v "$PWD:/src" -w /src golang:1.23-bookworm go test -race ./...
```

`GO_IMAGE` overrides the unit-test/format/vet image. `TRAEFIK_PORT` overrides the host port (also used temporarily by integration). Integration has a separate Compose project and removes its containers, network, and test certificate volume on exit. Its TLS stub owns the `api.abuseipdb.com` DNS alias **only inside that Docker network**, so the production HTTPS client runs unchanged without contacting AbuseIPDB or using a real key. The integration-only trust-all forwarded-header settings must never be copied into production.

## Configuration

Traefik calls `CreateConfig()` before decoding these flat, JSON-tagged fields. Example dynamic configuration (supply the actual secret securely):

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

`playground/dynamic.yml` is a working file-provider example; Compose mounts the plugin through Traefik's local-plugin mechanism. For a future published release, replace the local-plugin registration with `experimental.plugins.abuseipdb.moduleName` and a released `version`.

### Decision order

1. Resolve `RemoteAddr`. Ignore X-Forwarded-For unless the peer belongs to `trustedProxies`; then walk the chain right-to-left until the first untrusted hop. Multiple XFF lines are supported. Invalid addresses never reach the API and use the failure policy.
2. Static allow CIDRs win over static deny CIDRs. Deny CIDRs are applied **before** private-range skipping.
3. Skip private/special-use IPv4 and IPv6 by default, including CGNAT, loopback, link-local, ULA, and documentation ranges.
4. Use the per-instance TTL/LRU result, or share one in-flight `/check` for the canonical IP.
5. Honor `isWhitelisted`, then country allow, then country deny. Otherwise block when the score is **at least** `threshold` (default 90). With `blockCategories`, score blocking additionally requires a matching report category. Category filtering automatically requests `verbose=true`; without it, verbose is omitted by default. Country allow is an exemption, not an exclusive country allowlist. Whitelist/country allow override country deny; static deny remains authoritative.
6. Cache allow decisions for `cacheTTL`, deny decisions for `blockTTL`, and API failures for `errorTTL`. On failures, allow by default or deny with `failClosed: true`.

Duration strings must be positive; cache capacity must be positive; score is 0–100, max age 1–365 days, retries 0–1, category IDs 1–23, countries two ASCII letters (case-insensitive), response status 400–599.

### API behavior and lifecycle

- The API key is only in the `Key` header, never in a query, log, error body, or diagnostic header. Redirects are rejected to avoid forwarding credentials elsewhere. Error bodies are discarded within a bound; `/check` responses are limited to 4 MiB and checked for the queried IP and a valid score.
- `requestTimeout` covers the **whole lookup**, including the response body, retry, and backoff. At most one retry is made on network errors, 5xx, or 429. Other statuses are not retried. Retry-After seconds and HTTP dates are honored; if the wait exceeds the remaining timeout, fail immediately and retain an instance-wide cooldown to suppress further calls. Invalid/missing Retry-After uses one minute.
- Caches, singleflight, and cooldown are per middleware instance; reloads rebuild them. Multiple replicas/instances each consume their own API quota.
- Logs contain canonical IP, verdict, source, and sanitized lookup failures, not request URLs, bodies, headers, or raw upstream errors. `logDecision` is `all` (every decision), `block` (denials only), or `none` (silent) if IP logging is unwanted.

Deploy directly in front of your backend; upstream CDN/LB integration is outside this milestone's scope. Keep `trustedProxies` empty unless you explicitly control the proxy chain. Be aware that Traefik's own entrypoint forwarded-header policy applies before middleware execution.

Store secrets outside source control and Docker labels/dashboard-visible configuration. Traefik file-provider environment interpolation uses Go templates such as `apiKey: '{{ env "ABUSEIPDB_API_KEY" }}'`; plain `${...}` substitution is a Compose feature, not general Traefik file-provider expansion.
