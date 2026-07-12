package collector

import "time"

const (
	SchemaVersion = "1.0.0"
	SchemaID      = "evidencepack/tls@v1"
	ArtifactPath  = "artifacts/tls.json"
)

type Config struct {
	Endpoints       []Endpoint
	Timeout         time.Duration
	EndpointScanner EndpointScanner
	OnStatus        func(string)
	OnProgress      func(current int64, total int64, message string)
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
	Reachable   bool         `json:"reachable"`
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
	TLS10 bool `json:"tls_1_0"`
	TLS11 bool `json:"tls_1_1"`
	TLS12 bool `json:"tls_1_2"`
	TLS13 bool `json:"tls_1_3"`
}

type Certificate struct {
	SubjectCommonName  string    `json:"subject_common_name,omitempty"`
	IssuerCommonName   string    `json:"issuer_common_name,omitempty"`
	SerialNumber       string    `json:"serial_number,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	ExpiresInDays      int       `json:"expires_in_days"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	FingerprintSHA256  string    `json:"fingerprint_sha256,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm,omitempty"`
	ChainLength        int       `json:"chain_length"`
	TrustedChain       bool      `json:"trusted_chain"`
	HostnameValid      bool      `json:"hostname_valid"`
}

type Assessment struct {
	CertificateValid        bool     `json:"certificate_valid"`
	HostnameValid           bool     `json:"hostname_valid"`
	Expired                 bool     `json:"expired"`
	ExpiringSoon            bool     `json:"expiring_soon"`
	ModernProtocol          bool     `json:"modern_protocol"`
	LegacyProtocolSupported bool     `json:"legacy_protocol_supported"`
	Issues                  []string `json:"issues,omitempty"`
}

type Summary struct {
	TotalEndpoints             int  `json:"total_endpoints"`
	ReachablePct               int  `json:"reachable_pct"`
	CertificateValidPct        int  `json:"certificate_valid_pct"`
	HostnameValidPct           int  `json:"hostname_valid_pct"`
	ModernProtocolPct          int  `json:"modern_protocol_pct"`
	ExpiringSoonPct            int  `json:"expiring_soon_pct"`
	LegacyProtocolSupportedPct int  `json:"legacy_protocol_supported_pct"`
	AllCertificatesValid       bool `json:"all_certificates_valid"`
	AllModernProtocol          bool `json:"all_modern_protocol"`
}

type Diagnostics struct {
	EndpointErrors []string `json:"endpoint_errors,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}
