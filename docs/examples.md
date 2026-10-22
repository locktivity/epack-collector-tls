# Examples

## Basic Usage

### Single Endpoint

```yaml
stream: myorg/tls-posture

collectors:
  tls:
    source: locktivity/epack-collector-tls@^0.2
    config:
      endpoints:
        - app.example.com
```

Then run:

```bash
epack collect
```

### Multiple Endpoints and Ports

```yaml
stream: myorg/tls-posture

collectors:
  tls:
    source: locktivity/epack-collector-tls@^0.2
    config:
      endpoints:
        - app.example.com           # Primary web app
        - api.example.com:8443      # API on a custom port
        - login.example.com         # SSO entry point
        - status.example.com        # Status page
```

### Running Locally Through the SDK

`EPACK_COLLECTOR_CONFIG` takes the path to a JSON config file:

```bash
echo '{"endpoints":[{"host":"app.example.com","port":443}]}' > config.json
EPACK_COLLECTOR_CONFIG=config.json epack sdk run ./epack-collector-tls
```

## Sample Output

```json
{
  "protocol_version": 1,
  "data": {
    "schema_version": "1.0.0",
    "collected_at": "2026-07-12T10:30:00Z",
    "endpoints": [
      {
        "host": "app.example.com",
        "port": 443,
        "reachable": true,
        "tls": {
          "negotiated_version": "TLS 1.3",
          "negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
          "protocol_support": {
            "tls_1_0": false,
            "tls_1_1": false,
            "tls_1_2": true,
            "tls_1_3": true
          }
        },
        "certificate": {
          "subject_common_name": "app.example.com",
          "issuer_common_name": "E5",
          "serial_number": "301856080525954483946262561144304836989",
          "not_before": "2026-06-01T00:00:00Z",
          "not_after": "2026-09-28T23:59:59Z",
          "expires_in_days": 78,
          "dns_names": ["app.example.com"],
          "ip_addresses": [],
          "fingerprint_sha256": "9F2A417C6B8E0D3F5A1B2C4D6E8F0A1B3C5D7E9F1A3B5C7D9E1F3A5B7C9D0E2F",
          "signature_algorithm": "ECDSA-SHA384",
          "public_key_algorithm": "ECDSA",
          "chain_length": 2,
          "trusted_chain": true,
          "hostname_valid": true
        },
        "assessment": {
          "certificate_valid": true,
          "hostname_valid": true,
          "expired": false,
          "expiring_soon": false,
          "modern_protocol": true,
          "legacy_protocol_supported": false,
          "issues": []
        }
      },
      {
        "host": "api.example.com",
        "port": 8443,
        "reachable": true,
        "tls": {
          "negotiated_version": "TLS 1.2",
          "negotiated_cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          "protocol_support": {
            "tls_1_0": false,
            "tls_1_1": false,
            "tls_1_2": true,
            "tls_1_3": false
          }
        },
        "certificate": {
          "subject_common_name": "api.example.com",
          "issuer_common_name": "R11",
          "serial_number": "274377854701857781766707579337729355821",
          "not_before": "2026-05-04T00:00:00Z",
          "not_after": "2026-08-02T23:59:59Z",
          "expires_in_days": 21,
          "dns_names": ["api.example.com"],
          "ip_addresses": [],
          "fingerprint_sha256": "1D4E7A0C3F6B9E2D5A8C1F4B7E0A3D6C9F2B5E8A1D4C7F0B3E6A9D2C5F8B1E4A",
          "signature_algorithm": "SHA256-RSA",
          "public_key_algorithm": "RSA",
          "chain_length": 2,
          "trusted_chain": true,
          "hostname_valid": true
        },
        "assessment": {
          "certificate_valid": true,
          "hostname_valid": true,
          "expired": false,
          "expiring_soon": true,
          "modern_protocol": true,
          "legacy_protocol_supported": false,
          "issues": [
            "Certificate expires within 30 days"
          ]
        }
      }
    ],
    "summary": {
      "total_endpoints": 2,
      "reachable_count": 2,
      "reachable_pct": 100,
      "certificate_valid_count": 2,
      "certificate_valid_pct": 100,
      "hostname_valid_count": 2,
      "hostname_valid_pct": 100,
      "modern_protocol_count": 2,
      "modern_protocol_pct": 100,
      "expiring_soon_count": 1,
      "expiring_soon_pct": 50,
      "legacy_protocol_supported_count": 0,
      "legacy_protocol_supported_pct": 0,
      "all_certificates_valid": true,
      "all_modern_protocol": true
    }
  }
}
```

## Understanding the Output

### Assessment

Each endpoint includes an `assessment` object:

| Field | Description |
|-------|-------------|
| `certificate_valid` | `true` if the chain is trusted, the hostname matches, and the certificate is within its validity window |
| `hostname_valid` | `true` if the certificate is valid for the configured host |
| `expired` | `true` if the certificate is past its `not_after` date |
| `expiring_soon` | `true` if the certificate expires within 30 days |
| `modern_protocol` | `true` if TLS 1.2 or TLS 1.3 is supported |
| `legacy_protocol_supported` | `true` if TLS 1.0 or TLS 1.1 is accepted |
| `issues` | List of problems found |

### Summary Metrics

All percentages use configured endpoints as the denominator, so an endpoint that answered without completing a modern handshake counts against certificate and protocol percentages. Each percentage has a count beside it, such as `reachable_count`, the number of endpoints it counts, and is that count over `total_endpoints`, rounded down. A count and its percentage are left out when a value behind them could not be read.

| Field | Description |
|-------|-------------|
| `total_endpoints` | Number of endpoints scanned |
| `reachable_pct` | Percentage that completed a modern TLS handshake |
| `certificate_valid_pct` | Percentage with trusted, hostname-valid, unexpired certificates |
| `hostname_valid_pct` | Percentage whose certificate matches the configured host |
| `modern_protocol_pct` | Percentage supporting TLS 1.2 or TLS 1.3 |
| `expiring_soon_pct` | Percentage with certificates expiring within 30 days |
| `legacy_protocol_supported_pct` | Percentage accepting TLS 1.0 or TLS 1.1 |
| `all_certificates_valid` | `true` only if ALL endpoints have valid certificates |
| `all_modern_protocol` | `true` only if ALL endpoints support modern TLS |

### Diagnostics

When endpoints fail to respond, a `diagnostics` block records one entry per failure:

```json
"diagnostics": {
  "endpoint_errors": [
    "old.example.com:443: TLS handshake failed: dial tcp: connection refused"
  ]
}
```

### Collector Result

The collector also emits `artifacts/tls.collector-result.json`. It lists a gap for each value left out, such as a TLS version whose probe timed out, with a code like `timeout` or `vendor_error` and the probe that failed, such as `tls.probe.tls10`. It also counts the connections the collector made and lists the run's steps, `handshake` and then `protocol_support`, with each step's times and connections.

### Pass Criteria

For a clean TLS posture:
- `all_certificates_valid` should be `true`
- `all_modern_protocol` should be `true`
- `legacy_protocol_supported_pct` should be `0`
- `expiring_soon_pct` should be `0`

## CI/CD Integration

### GitHub Actions

```yaml
name: Collect Evidence

on:
  schedule:
    - cron: "0 0 * * 1"  # Weekly on Monday
  workflow_dispatch:

jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install epack
        run: |
          curl -sSL https://github.com/locktivity/epack/releases/latest/download/epack-linux-amd64 -o epack
          chmod +x epack
          sudo mv epack /usr/local/bin/

      - name: Collect evidence
        run: epack collect --frozen

      - name: Upload pack
        uses: actions/upload-artifact@v4
        with:
          name: evidence-pack
          path: "*.pack"
```
