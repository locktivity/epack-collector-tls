package collector

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

const expiringSoonDays = 30

// Offer every implemented cipher suite, including the insecure ones Go drops
// from its defaults since 1.22, so legacy-only servers are detected instead of
// probing as unsupported.
var probeCipherSuites = allCipherSuiteIDs()

func ScanEndpoint(ctx context.Context, endpoint Endpoint, timeout time.Duration) EndpointResult {
	result := EndpointResult{
		Host:   endpoint.Host,
		Port:   endpoint.Port,
		Errors: []string{},
	}
	now := time.Now().UTC()

	state, err := handshake(ctx, endpoint, tls.VersionTLS12, 0, timeout)
	if err != nil {
		result.Errors = append(result.Errors, "TLS handshake failed: "+err.Error())
		result.TLS = &TLSDetails{ProtocolSupport: probeProtocols(ctx, endpoint, 0, timeout)}
		result.Assessment = assess(result, now)
		return result
	}

	result.Reachable = true
	result.TLS = &TLSDetails{
		NegotiatedVersion:     tlsVersionName(state.Version),
		NegotiatedCipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ProtocolSupport:       probeProtocols(ctx, endpoint, state.Version, timeout),
	}
	if len(state.PeerCertificates) > 0 {
		result.Certificate = summarizeCertificate(endpoint.Host, state.PeerCertificates, now)
	}
	result.Assessment = assess(result, now)
	return result
}

func handshake(ctx context.Context, endpoint Endpoint, minVersion uint16, maxVersion uint16, timeout time.Duration) (tls.ConnectionState, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	address := net.JoinHostPort(endpoint.Host, fmt.Sprintf("%d", endpoint.Port))
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(handshakeCtx, "tcp", address)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = rawConn.Close() }()

	_ = rawConn.SetDeadline(time.Now().Add(timeout))
	// #nosec G402 -- verification is performed manually so invalid certificates can be reported as evidence.
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         endpoint.Host,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		CipherSuites:       probeCipherSuites,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tlsConn.ConnectionState(), nil
}

func probeProtocols(ctx context.Context, endpoint Endpoint, negotiated uint16, timeout time.Duration) ProtocolSupport {
	support := ProtocolSupport{
		TLS12: negotiated == tls.VersionTLS12,
		TLS13: negotiated == tls.VersionTLS13,
	}
	support.TLS10 = probeProtocol(ctx, endpoint, tls.VersionTLS10, timeout)
	support.TLS11 = probeProtocol(ctx, endpoint, tls.VersionTLS11, timeout)
	if !support.TLS12 {
		support.TLS12 = probeProtocol(ctx, endpoint, tls.VersionTLS12, timeout)
	}
	if !support.TLS13 {
		support.TLS13 = probeProtocol(ctx, endpoint, tls.VersionTLS13, timeout)
	}
	return support
}

func probeProtocol(ctx context.Context, endpoint Endpoint, version uint16, timeout time.Duration) bool {
	_, err := handshake(ctx, endpoint, version, version, timeout)
	return err == nil
}

func allCipherSuiteIDs() []uint16 {
	var ids []uint16
	for _, suite := range tls.CipherSuites() {
		ids = append(ids, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		ids = append(ids, suite.ID)
	}
	return ids
}

func summarizeCertificate(host string, chain []*x509.Certificate, now time.Time) *Certificate {
	leaf := chain[0]
	cert := &Certificate{
		SubjectCommonName:  leaf.Subject.CommonName,
		IssuerCommonName:   leaf.Issuer.CommonName,
		SerialNumber:       leaf.SerialNumber.String(),
		NotBefore:          leaf.NotBefore,
		NotAfter:           leaf.NotAfter,
		ExpiresInDays:      int(leaf.NotAfter.Sub(now).Hours() / 24),
		DNSNames:           leaf.DNSNames,
		IPAddresses:        ipStrings(leaf.IPAddresses),
		FingerprintSHA256:  fingerprintSHA256(leaf.Raw),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
		ChainLength:        len(chain),
		HostnameValid:      leaf.VerifyHostname(host) == nil,
	}
	cert.TrustedChain = verifyChain(host, chain, now) == nil
	return cert
}

func verifyChain(host string, chain []*x509.Certificate, now time.Time) error {
	if len(chain) == 0 {
		return fmt.Errorf("no certificates")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		CurrentTime:   now,
		Intermediates: intermediates,
	})
	return err
}

func assess(result EndpointResult, now time.Time) Assessment {
	assessment := Assessment{}
	var issues []string

	if !result.Reachable {
		issues = append(issues, "Endpoint was not reachable over modern TLS")
	}

	if result.Certificate == nil {
		issues = append(issues, "No certificate was presented")
	} else {
		certificate := *result.Certificate
		notYetValid := certificate.NotBefore.After(now)
		assessment.HostnameValid = certificate.HostnameValid
		assessment.Expired = certificateExpired(certificate, now)
		assessment.ExpiringSoon = !assessment.Expired && certificate.ExpiresInDays <= expiringSoonDays
		assessment.CertificateValid = certificate.TrustedChain && certificate.HostnameValid &&
			!assessment.Expired && !notYetValid

		if !certificate.TrustedChain {
			issues = append(issues, "Certificate chain is not trusted")
		}
		if !certificate.HostnameValid {
			issues = append(issues, "Certificate hostname does not match the endpoint")
		}
		if notYetValid {
			issues = append(issues, "Certificate is not yet valid")
		}
		if assessment.Expired {
			issues = append(issues, "Certificate is expired")
		} else if assessment.ExpiringSoon {
			issues = append(issues, "Certificate expires within 30 days")
		}
	}

	if result.TLS == nil {
		issues = append(issues, "TLS protocol support was not checked")
	} else {
		support := result.TLS.ProtocolSupport
		assessment.ModernProtocol = support.TLS12 || support.TLS13
		assessment.LegacyProtocolSupported = support.TLS10 || support.TLS11
		if !assessment.ModernProtocol {
			issues = append(issues, "TLS 1.2 or TLS 1.3 support was not detected")
		}
		if assessment.LegacyProtocolSupported {
			issues = append(issues, "TLS 1.0 or TLS 1.1 is supported")
		}
	}

	assessment.Issues = issues
	return assessment
}

func certificateExpired(cert Certificate, now time.Time) bool {
	return !cert.NotAfter.After(now)
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func fingerprintSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func ipStrings(ips []net.IP) []string {
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return result
}
