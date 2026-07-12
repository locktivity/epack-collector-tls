# TLS Posture Collector

The TLS Posture Collector checks configured public endpoints for certificate health and protocol support.

## What It Collects

This collector connects to each configured endpoint and records transport security posture:

- **Reachability**: Whether the endpoint completes a TLS 1.2+ handshake
- **Negotiated TLS**: The protocol version and cipher suite chosen by the server
- **Protocol Support**: Individual probes for TLS 1.0, 1.1, 1.2, and 1.3
- **Certificate**: Leaf certificate details including:
  - Subject and issuer common names
  - Validity window and days until expiry
  - DNS and IP subject alternative names
  - SHA256 fingerprint
  - Chain trust against system roots
  - Hostname match for the configured host
- **Assessment**: Per-endpoint evaluation (valid certificate, modern protocol, legacy protocol, issues)

## What It Does Not Collect

- HTTP response bodies, cookies, or authenticated content
- Subdomains discovered from DNS, certificate transparency, or search
- Private keys, secrets, or credentials
- STARTTLS posture for SMTP, IMAP, LDAP, or database protocols

The collector only connects to endpoints you explicitly configure. There is no discovery.

## Use Cases

- **Third-party risk assessments**: Provide evidence of transport security posture to customers and auditors
- **Compliance monitoring**: Verify public endpoints use trusted certificates and modern TLS
- **Expiry tracking**: Catch certificates entering the 30-day renewal window
- **Legacy protocol cleanup**: Find endpoints still accepting TLS 1.0 or 1.1

## How It Works

1. The collector receives a list of endpoints from your configuration
2. For each endpoint, it performs a TLS 1.2+ handshake and records the negotiated version, cipher suite, and certificate chain
3. It probes each remaining TLS version individually to build the protocol support matrix
4. The certificate chain is verified against system roots and the configured hostname
5. Per-endpoint assessment is computed (certificate validity, protocol posture, issues)
6. Summary statistics are aggregated across all configured endpoints
7. Output is wrapped in the epack collector protocol envelope

Certificate verification happens after the handshake, so invalid, expired, or mismatched certificates are reported as evidence rather than causing collection to fail.

Probes offer every cipher suite Go implements, including legacy suites excluded from modern client defaults, so servers that only speak old cipher suites are still detected. A `false` protocol support value means no handshake succeeded at that version with any implemented suite.

Summary percentages use all configured endpoints as the denominator. An unreachable endpoint counts against `certificate_valid_pct` and `modern_protocol_pct`, since its posture could not be demonstrated.

## Authentication

This collector does not require authentication - it only performs TLS handshakes against public endpoints.

See [Configuration](configuration.md) for setup instructions.
