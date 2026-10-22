package collector

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
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

	result, gaps := scanOne(endpoint)
	if result.Reachable == nil || !*result.Reachable {
		t.Fatalf("Reachable = %v; errors: %v", result.Reachable, result.Errors)
	}
	if result.Certificate == nil {
		t.Fatal("Certificate = nil, want certificate summary")
	}
	if result.TLS == nil {
		t.Fatal("TLS = nil, want TLS details")
	}
	if result.Assessment.ModernProtocol == nil || !*result.Assessment.ModernProtocol {
		t.Errorf("ModernProtocol = %v, want true", result.Assessment.ModernProtocol)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none", gaps)
	}
}

func TestAssessCertificateIssues(t *testing.T) {
	result := EndpointResult{
		Reachable: ptr(true),
		TLS: &TLSDetails{ProtocolSupport: ProtocolSupport{
			TLS10: ptr(true),
			TLS11: ptr(false),
			TLS12: ptr(true),
			TLS13: ptr(false),
		}},
		Certificate: &Certificate{
			NotAfter:      time.Now().Add(10 * 24 * time.Hour),
			ExpiresInDays: 10,
			TrustedChain:  false,
			HostnameValid: false,
		},
	}

	assessment := assess(result, time.Now().UTC())
	if assessment.CertificateValid == nil || *assessment.CertificateValid {
		t.Errorf("CertificateValid = %v, want false", assessment.CertificateValid)
	}
	if assessment.ExpiringSoon == nil || !*assessment.ExpiringSoon {
		t.Errorf("ExpiringSoon = %v, want true", assessment.ExpiringSoon)
	}
	if assessment.LegacyProtocolSupported == nil || !*assessment.LegacyProtocolSupported {
		t.Errorf("LegacyProtocolSupported = %v, want true", assessment.LegacyProtocolSupported)
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
	cert := summarizeCertificate("app.example.com", []*x509.Certificate{template}, nil, now)
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
		Reachable: ptr(true),
		TLS:       &TLSDetails{ProtocolSupport: ProtocolSupport{TLS12: ptr(false), TLS13: ptr(true)}},
		Certificate: &Certificate{
			NotBefore:     now.Add(24 * time.Hour),
			NotAfter:      now.Add(90 * 24 * time.Hour),
			ExpiresInDays: 90,
			TrustedChain:  true,
			HostnameValid: true,
		},
	}

	assessment := assess(result, now)
	if assessment.CertificateValid == nil || *assessment.CertificateValid {
		t.Errorf("CertificateValid = %v, want false", assessment.CertificateValid)
	}
	if assessment.Expired == nil || *assessment.Expired {
		t.Errorf("Expired = %v, want false", assessment.Expired)
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

	result, gaps := scanOne(endpoint)
	if result.Reachable == nil || *result.Reachable {
		t.Fatalf("Reachable = %v, want false for a TLS 1.0-only server", result.Reachable)
	}
	if result.TLS == nil || result.TLS.ProtocolSupport.TLS10 == nil || !*result.TLS.ProtocolSupport.TLS10 {
		t.Fatalf("ProtocolSupport = %+v, want TLS10 true", result.TLS)
	}
	if result.Assessment.LegacyProtocolSupported == nil || !*result.Assessment.LegacyProtocolSupported {
		t.Errorf("LegacyProtocolSupported = %v, want true", result.Assessment.LegacyProtocolSupported)
	}
	if result.Assessment.ModernProtocol == nil || *result.Assessment.ModernProtocol {
		t.Errorf("ModernProtocol = %v, want false", result.Assessment.ModernProtocol)
	}
	if len(result.Errors) == 0 {
		t.Error("Errors is empty, want handshake failure recorded")
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none: the server turned the modern handshake down", gaps)
	}
}

// A handshake that times out or is reset after the dial counts against its
// operation in the collector result, with the code of the gaps it leaves.
func TestHandshakeFailuresCountAgainstTheirOperation(t *testing.T) {
	silent := localServer(t, func(net.Conn) {})
	reset := localServer(t, func(conn net.Conn) {
		_ = conn.(*net.TCPConn).SetLinger(0)
		_ = conn.Close()
	})
	run := func(ctx componentsdk.CollectorContext) error {
		dialer := componentsdk.NewDialer(ctx)
		posture := Collect(ctx.Context(), Config{
			Endpoints: []Endpoint{silent, reset},
			Dial:      dialer.DialContext,
			Timeout:   200 * time.Millisecond,
			Now:       func() time.Time { return componentsdk.Now(ctx) },
			Recorder:  componentsdk.Records(ctx),
		})
		return ctx.Emit([]componentsdk.CollectedArtifact{
			componentsdk.JSONArtifact(ArtifactPath, posture, componentsdk.ArtifactMeta{Schema: SchemaID}),
		})
	}
	var dialer net.Dialer
	res := componentsdk.RunInProcess(Spec("test", "test"), run, componentsdk.InProcessOptions{Dial: dialer.DialContext})
	if res.Result == nil {
		t.Fatalf("no collector result; exit %d: %s", res.ExitCode, res.Stderr)
	}

	want := map[componentsdk.Code]int{componentsdk.CodeTimeout: 1, componentsdk.CodeVendorError: 1}
	if got := len(res.Result.Calls.Operations); got != 1+len(probes) {
		t.Errorf("operations = %d, want the handshake and %d probes", got, len(probes))
	}
	for _, op := range res.Result.Calls.Operations {
		if op.Calls != 2 || !maps.Equal(op.Errors, want) {
			t.Errorf("%s: %d calls with errors %v, want 2 with %v", op.Name, op.Calls, op.Errors, want)
		}
	}
	codes := map[string]componentsdk.Code{}
	for _, g := range res.Result.Gaps {
		codes[g.Pointer] = g.Code
	}
	if codes["/endpoints/0/reachable"] != componentsdk.CodeTimeout || codes["/endpoints/1/reachable"] != componentsdk.CodeVendorError {
		t.Errorf("reachable gaps = %q and %q, want timeout and vendor_error", codes["/endpoints/0/reachable"], codes["/endpoints/1/reachable"])
	}
}

// localServer listens on a loopback port and hands each connection it accepts
// to handle. The listener and every connection close when the test ends.
func localServer(t *testing.T, handle func(net.Conn)) Endpoint {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			handle(conn)
		}
	}()
	host, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatalf("Atoi returned error: %v", err)
	}
	endpoint, err := NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}
	return endpoint
}

// scanOne scans endpoint as the run's steps do, and returns its result and
// the values left out of it.
func scanOne(endpoint Endpoint) (EndpointResult, []gap) {
	var dialer net.Dialer
	s := scanner{dial: dialer.DialContext, timeout: 5 * time.Second}
	e := newEndpointScan(0, endpoint, &componentsdk.Recorder{})
	e.now = time.Now()
	s.connect(context.Background(), &e)
	s.probe(context.Background(), &e)
	e.assess()
	return e.result, e.gaps
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
