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
2. In its first step, `handshake`, it performs a TLS 1.2+ handshake with each endpoint and records the negotiated version, cipher suite, and certificate chain
3. In its second step, `protocol_support`, it probes each endpoint's remaining TLS versions individually to build the protocol support matrix
4. The certificate chain is verified against system roots, and the hostname match and validity window are checked on their own
5. Per-endpoint assessment is computed (certificate validity, protocol posture, issues)
6. Summary counts and percentages are aggregated across all configured endpoints
7. Output is wrapped in the epack collector protocol envelope

Certificate verification happens after the handshake, so invalid, expired, or mismatched certificates are reported as evidence rather than causing collection to fail.

An expired certificate or one for another hostname still reads `trusted_chain: true` when it chains to a trusted root; `expired` and `hostname_valid` report those problems.

Probes offer every cipher suite Go implements, including legacy suites excluded from modern client defaults, so servers that only speak old cipher suites are still detected. A `false` protocol support value means the endpoint turned that version down, with a TLS alert or a reply that is not TLS, or that nothing accepted the connection. A probe that times out or fails another way leaves its value out instead.

Summary percentages use all configured endpoints as the denominator. An endpoint that answered without completing a modern handshake, such as one that refuses the connection or speaks plain HTTP, counts against `certificate_valid_pct` and `modern_protocol_pct`. Each percentage has the count it is taken of beside it, such as `certificate_valid_count`, and is that count over `total_endpoints`, rounded down.

## Partial Collection

A value the collector could not read is left out of `artifacts/tls.json` rather than written as `false` or 0, and a summary count and percentage over it are left out too. The collector result artifact, `artifacts/tls.collector-result.json`, records a gap for each value left out, with the reason and the handshake or probe that failed. It also lists the connections the collector made and the run's two steps. The run fails only when the configuration is invalid.

## Authentication

This collector does not require authentication - it only performs TLS handshakes against public endpoints.

See [Configuration](configuration.md) for setup instructions.
