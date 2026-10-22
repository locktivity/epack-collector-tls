# epack-collector-tls

Collects public TLS certificate and protocol posture for a list of endpoints.

## What it collects

- **Reachability**: Whether each endpoint completes a modern TLS handshake
- **Negotiated TLS**: Protocol version and cipher suite from the primary handshake
- **Protocol Support**: Per-version probes for TLS 1.0, 1.1, 1.2, and 1.3
- **Certificate**: Identity, validity window, issuer, SANs, fingerprint, chain trust, and hostname match
- **Assessment**: Per-endpoint pass/fail evaluation with a list of issues found

See [docs/overview.md](docs/overview.md) for detailed documentation.

## Quick Start

```yaml
# epack.yaml
collectors:
  tls:
    source: locktivity/epack-collector-tls@^0.2
    config:
      endpoints:
        - app.example.com
        - api.example.com:8443
```

```bash
epack collect
```

## Binary Download

Download pre-built binaries with SLSA Level 3 provenance from the [Releases](https://github.com/locktivity/epack-collector-tls/releases) page.

Each release includes:
- Binaries for linux/darwin on amd64/arm64
- SLSA provenance attestations (`.sigstore.json`)
- SHA256 checksums

## Development

```bash
# Build
make build

# Run tests
make test

# Lint
make lint

# Conformance at the epack version go.mod pins, as CI runs it
make conformance

# Rewrite docs/schema/trace-map.json after changing collector code or tests
make trace-map

# SDK test (requires epack)
make sdk-test

# SDK run (requires epack)
make sdk-run
```

## Testing

```bash
# Unit tests (spin up local TLS servers, no external network required)
go test -race -v ./...
```

## Release

Releases are automated via GitHub Actions on version tags:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow:
1. Runs tests and conformance checks
2. Builds binaries for all platforms with SLSA Level 3 provenance
3. Creates a GitHub release with all artifacts

## Output Schema

The collector outputs to `artifacts/tls.json`. See [docs/schema/v1.0.0.json](docs/schema/v1.0.0.json) for the full JSON schema.

### Key Fields

| Field | Description |
|-------|-------------|
| `certificate.trusted_chain` | `true` if the chain leads to a trusted root. Expiry and the hostname match are reported on their own |
| `assessment.certificate_valid` | `true` if the chain is trusted, the hostname matches, and the certificate is within its validity window |
| `assessment.legacy_protocol_supported` | `true` if the endpoint accepts TLS 1.0 or TLS 1.1 |
| `summary.all_certificates_valid` | `true` only if ALL endpoints have valid certificates |
| `summary.all_modern_protocol` | `true` only if ALL endpoints support TLS 1.2 or TLS 1.3 |

Each summary percentage has the count it is taken of beside it, such as
`certificate_valid_count` for `certificate_valid_pct`, and is that count over
`total_endpoints`, rounded down.

### Partial collection and exit codes

The run fails only when the configuration is invalid. Otherwise it exits 0 and
emits the posture of every configured endpoint.

| Exit | Code | When |
|---|---|---|
| 0 | | The run collected, even if some values were left out |
| 2 | `config_invalid` | `endpoints` is missing or empty, is not a list, or has an invalid host or port |

Each endpoint is judged only on what it answered. A refused connection, a host
name that does not exist, a TLS alert, and a reply that is not TLS are answers:
the endpoint reads as not reachable over modern TLS, and a TLS version it turns
down reads as `false`. A handshake that times out, is reset, or fails another
way is not an answer, so the values that depend on it are left out rather than
written as `false`.

The artifact `artifacts/tls.collector-result.json` lists a gap for each value
left out, with a code such as `timeout` or `vendor_error` and the handshake or
probe that failed, such as `tls.probe.tls10`. It also lists the connections
the collector made and the run's two steps: the modern handshake with every
endpoint, then the probes of the remaining TLS versions. A summary
count and its percentage are left out when a value behind them was left out,
and so is `all_certificates_valid` or `all_modern_protocol`, unless an
endpoint that was read already makes it `false`. The error text stays in each
endpoint's `errors` and in `diagnostics.endpoint_errors`.

### Pass Criteria

For a clean TLS posture:
- `all_certificates_valid` should be `true`
- `all_modern_protocol` should be `true`
- `legacy_protocol_supported_pct` should be `0`
- `expiring_soon_pct` should be `0` (certificates renewed ahead of the 30-day window)

## Documentation

- [Overview](docs/overview.md) - What it collects and how it works
- [Configuration](docs/configuration.md) - Setup and options
- [Examples](docs/examples.md) - Usage examples and sample output
- [Schema](docs/schema/v1.0.0.json) - JSON schema for output

## License

Apache 2.0 - see [LICENSE](LICENSE)
