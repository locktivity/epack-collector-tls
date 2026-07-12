package collector

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestScanEndpointAgainstLocalTLSServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = listener
	server.StartTLS()
	defer server.Close()

	host, portString, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}
	port, err := net.LookupPort("tcp", portString)
	if err != nil {
		t.Fatalf("LookupPort returned error: %v", err)
	}
	endpoint, err := NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}

	result := ScanEndpoint(context.Background(), endpoint, 5*time.Second)
	if !result.Reachable {
		t.Fatalf("Reachable = false; errors: %v", result.Errors)
	}
	if result.Certificate == nil {
		t.Fatal("Certificate = nil, want certificate summary")
	}
	if result.TLS == nil {
		t.Fatal("TLS = nil, want TLS details")
	}
	if !result.Assessment.ModernProtocol {
		t.Error("ModernProtocol = false, want true")
	}
}

func TestAssessCertificateIssues(t *testing.T) {
	result := EndpointResult{
		Reachable: true,
		TLS: &TLSDetails{ProtocolSupport: ProtocolSupport{
			TLS10: true,
			TLS12: true,
		}},
		Certificate: &Certificate{
			NotAfter:      time.Now().Add(10 * 24 * time.Hour),
			ExpiresInDays: 10,
			TrustedChain:  false,
			HostnameValid: false,
		},
	}

	assessment := assess(result, time.Now().UTC())
	if assessment.CertificateValid {
		t.Error("CertificateValid = true, want false")
	}
	if !assessment.ExpiringSoon {
		t.Error("ExpiringSoon = false, want true")
	}
	if !assessment.LegacyProtocolSupported {
		t.Error("LegacyProtocolSupported = false, want true")
	}
	if len(assessment.Issues) != 4 {
		t.Errorf("len(Issues) = %d, want 4; issues: %v", len(assessment.Issues), assessment.Issues)
	}
}

func TestSummarizeCertificate(t *testing.T) {
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:       mustSerial(t, "1234"),
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.Add(90 * 24 * time.Hour),
		DNSNames:           []string{"app.example.com"},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
	}
	cert := summarizeCertificate("app.example.com", []*x509.Certificate{template}, now)
	if !cert.HostnameValid {
		t.Error("HostnameValid = false, want true")
	}
	if cert.ExpiresInDays != 90 {
		t.Errorf("ExpiresInDays = %d, want 90", cert.ExpiresInDays)
	}
	if cert.FingerprintSHA256 == "" {
		t.Error("FingerprintSHA256 is blank")
	}
}

func TestAssessNotYetValidCertificate(t *testing.T) {
	now := time.Now().UTC()
	result := EndpointResult{
		Reachable: true,
		TLS:       &TLSDetails{ProtocolSupport: ProtocolSupport{TLS13: true}},
		Certificate: &Certificate{
			NotBefore:     now.Add(24 * time.Hour),
			NotAfter:      now.Add(90 * 24 * time.Hour),
			ExpiresInDays: 90,
			TrustedChain:  true,
			HostnameValid: true,
		},
	}

	assessment := assess(result, now)
	if assessment.CertificateValid {
		t.Error("CertificateValid = true, want false")
	}
	if assessment.Expired {
		t.Error("Expired = true, want false")
	}
	if !slices.Contains(assessment.Issues, "Certificate is not yet valid") {
		t.Errorf("Issues = %v, want not-yet-valid issue", assessment.Issues)
	}
}

func TestScanEndpointDetectsLegacyOnlyServer(t *testing.T) {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedRSACertificate(t)},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	})
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				_ = conn.Close()
			}(conn)
		}
	}()

	host, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}
	port, err := net.LookupPort("tcp", portString)
	if err != nil {
		t.Fatalf("LookupPort returned error: %v", err)
	}
	endpoint, err := NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}

	result := ScanEndpoint(context.Background(), endpoint, 5*time.Second)
	if result.Reachable {
		t.Fatal("Reachable = true, want false for a TLS 1.0-only server")
	}
	if result.TLS == nil || !result.TLS.ProtocolSupport.TLS10 {
		t.Fatalf("ProtocolSupport = %+v, want TLS10 true", result.TLS)
	}
	if !result.Assessment.LegacyProtocolSupported {
		t.Error("LegacyProtocolSupported = false, want true")
	}
	if result.Assessment.ModernProtocol {
		t.Error("ModernProtocol = true, want false")
	}
	if len(result.Errors) == 0 {
		t.Error("Errors is empty, want handshake failure recorded")
	}
}

func selfSignedRSACertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func mustSerial(t *testing.T, value string) *big.Int {
	t.Helper()
	serial, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid serial %q", value)
	}
	return serial
}
