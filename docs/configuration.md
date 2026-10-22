# Configuration

## Basic Setup

The TLS collector connects to public endpoints and does not require authentication.

```yaml
collectors:
  tls:
    source: locktivity/epack-collector-tls@^0.2
    config:
      endpoints:
        - app.example.com
        - api.example.com:8443
```

## Configuration Options

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `endpoints` | array | Yes | - | Endpoints to scan, as strings or objects |

## Endpoint Formats

Each endpoint can be a string or an object.

String form:

```yaml
endpoints:
  - app.example.com            # port defaults to 443
  - api.example.com:8443       # explicit port
  - https://login.example.com  # scheme prefix is stripped
  - "[2001:db8::1]:8443"       # IPv6 addresses use brackets with a port
```

Object form:

```yaml
endpoints:
  - host: app.example.com
    port: 443
  - host: api.example.com      # port defaults to 443
```

Hosts must be DNS names or IP addresses. DNS names are normalized to lowercase and must use valid DNS labels. `port` must be between 1 and 65535.

## Network Requirements

The runner needs outbound TCP access to every configured endpoint. Each endpoint is checked with several short handshakes (one per TLS version not already established), each bounded by a 10 second timeout.

## Troubleshooting

**"endpoints is required"**

The `endpoints` field must be set in your config:

```yaml
config:
  endpoints:
    - app.example.com  # Required - at least one endpoint
```

**"TLS handshake failed"**

If an endpoint reports a handshake failure:
- Verify the host and port are correct and the service is running
- Check that the runner has outbound network access to the endpoint
- Confirm the endpoint actually speaks TLS on that port (not plain HTTP)

A modern handshake the server turns down still triggers the per-version probes, so a TLS 1.0-only server shows up with `tls_1_0: true` and `legacy_protocol_supported: true`. A refused connection or a host name that does not exist reads as not reachable, with every TLS version `false`.

**Protocol support shows `false` unexpectedly**

Probes offer every cipher suite Go implements, including legacy suites, but a server requiring a cipher suite Go does not implement will still probe as unsupported. A `false` means the endpoint turned that version down or refused the connection, not proof the version is disabled.

**Values are missing**

When a handshake times out, is reset, or fails another way, the values that depend on it are left out rather than written as `false`, and so is any summary percentage over them. The run still succeeds. `artifacts/tls.collector-result.json` lists each value left out with a code such as `timeout` and the handshake or probe that failed, and `diagnostics.endpoint_errors` has the error text.

**Percentages look low**

Summary percentages count all configured endpoints. An endpoint that answered without completing a modern handshake counts against `certificate_valid_pct` and `modern_protocol_pct`. Check `diagnostics.endpoint_errors` for the failing endpoints.
