package collector

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const (
	SchemaVersion = "1.0.0"
	SchemaID      = "evidencepack/tls@v1"
	ArtifactPath  = "artifacts/tls.json"
)

type Config struct {
	Endpoints []Endpoint
	Timeout   time.Duration
	Dial      func(ctx context.Context, network, address string) (net.Conn, error)
	// RootCAs is the pool certificate chains are verified against. Nil means
	// the system's roots.
	RootCAs  *x509.CertPool
	Now      func() time.Time
	Recorder *componentsdk.Recorder
	// OnProgress reports each endpoint a step reaches. A step's title is the
	// run's status line, which componentsdk.StartStep prints.
	OnProgress func(current int64, total int64, message string)
}

type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type TLSPosture struct {
	SchemaVersion string           `json:"schema_version"`
	CollectedAt   time.Time        `json:"collected_at"`
	Endpoints     []EndpointResult `json:"endpoints"`
	Summary       Summary          `json:"summary"`
	Diagnostics   *Diagnostics     `json:"diagnostics,omitempty"`
}

type EndpointResult struct {
	Host        string       `json:"host"`
	Port        int          `json:"port"`
	Reachable   *bool        `json:"reachable,omitempty"`
	TLS         *TLSDetails  `json:"tls,omitempty"`
	Certificate *Certificate `json:"certificate,omitempty"`
	Assessment  Assessment   `json:"assessment"`
	Errors      []string     `json:"errors,omitempty"`
}

type TLSDetails struct {
	NegotiatedVersion     string          `json:"negotiated_version,omitempty"`
	NegotiatedCipherSuite string          `json:"negotiated_cipher_suite,omitempty"`
	ProtocolSupport       ProtocolSupport `json:"protocol_support"`
}

type ProtocolSupport struct {
	TLS10 *bool `json:"tls_1_0,omitempty"`
	TLS11 *bool `json:"tls_1_1,omitempty"`
	TLS12 *bool `json:"tls_1_2,omitempty"`
	TLS13 *bool `json:"tls_1_3,omitempty"`
}

type Certificate struct {
	SubjectCommonName  string    `json:"subject_common_name,omitempty"`
	IssuerCommonName   string    `json:"issuer_common_name,omitempty"`
	SerialNumber       string    `json:"serial_number,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	ExpiresInDays      int       `json:"expires_in_days"`
	DNSNames           []string  `json:"dns_names"`
	IPAddresses        []string  `json:"ip_addresses"`
	FingerprintSHA256  string    `json:"fingerprint_sha256,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm,omitempty"`
	ChainLength        int       `json:"chain_length"`
	TrustedChain       bool      `json:"trusted_chain"`
	HostnameValid      bool      `json:"hostname_valid"`
}

type Assessment struct {
	CertificateValid        *bool    `json:"certificate_valid,omitempty"`
	HostnameValid           *bool    `json:"hostname_valid,omitempty"`
	Expired                 *bool    `json:"expired,omitempty"`
	ExpiringSoon            *bool    `json:"expiring_soon,omitempty"`
	ModernProtocol          *bool    `json:"modern_protocol,omitempty"`
	LegacyProtocolSupported *bool    `json:"legacy_protocol_supported,omitempty"`
	Issues                  []string `json:"issues"`
}

type Summary struct {
	TotalEndpoints               int   `json:"total_endpoints"`
	ReachableCount               *int  `json:"reachable_count,omitempty"`
	ReachablePct                 *int  `json:"reachable_pct,omitempty"`
	CertificateValidCount        *int  `json:"certificate_valid_count,omitempty"`
	CertificateValidPct          *int  `json:"certificate_valid_pct,omitempty"`
	HostnameValidCount           *int  `json:"hostname_valid_count,omitempty"`
	HostnameValidPct             *int  `json:"hostname_valid_pct,omitempty"`
	ModernProtocolCount          *int  `json:"modern_protocol_count,omitempty"`
	ModernProtocolPct            *int  `json:"modern_protocol_pct,omitempty"`
	ExpiringSoonCount            *int  `json:"expiring_soon_count,omitempty"`
	ExpiringSoonPct              *int  `json:"expiring_soon_pct,omitempty"`
	LegacyProtocolSupportedCount *int  `json:"legacy_protocol_supported_count,omitempty"`
	LegacyProtocolSupportedPct   *int  `json:"legacy_protocol_supported_pct,omitempty"`
	AllCertificatesValid         *bool `json:"all_certificates_valid,omitempty"`
	AllModernProtocol            *bool `json:"all_modern_protocol,omitempty"`
}

type Diagnostics struct {
	EndpointErrors []string `json:"endpoint_errors,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

func ptr[T any](v T) *T {
	return &v
}
