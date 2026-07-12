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
    source: locktivity/epack-collector-tls@^0.1
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
| `assessment.certificate_valid` | `true` if the chain is trusted, the hostname matches, and the certificate is within its validity window |
| `assessment.legacy_protocol_supported` | `true` if the endpoint accepts TLS 1.0 or TLS 1.1 |
| `summary.all_certificates_valid` | `true` only if ALL endpoints have valid certificates |
| `summary.all_modern_protocol` | `true` only if ALL endpoints support TLS 1.2 or TLS 1.3 |

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
