package collector

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
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

// A certificate with no fixed expiry has a not_after in the year 9999
// (RFC 5280 section 4.1.2.5). That is more than a time.Duration holds.
func TestSummarizeCertificateExpiresInDays(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 500_000_000, time.UTC)
	for _, test := range []struct {
		name     string
		notAfter time.Time
		want     int
	}{
		{"half a second short of 90 days", now.Truncate(time.Second).Add(90 * 24 * time.Hour), 89},
		{"no fixed expiry", time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), 2912135},
	} {
		t.Run(test.name, func(t *testing.T) {
			leaf := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: test.notAfter}
			cert := summarizeCertificate("app.example.com", []*x509.Certificate{leaf}, nil, now)
			if cert.ExpiresInDays != test.want {
				t.Errorf("ExpiresInDays = %d for not_after %s, want %d", cert.ExpiresInDays, test.notAfter.Format(time.RFC3339), test.want)
			}
		})
	}
}

// A signature algorithm without a name in crypto/x509 reads as its object
// identifier from the certificate.
func TestSummarizeCertificateSignatureAlgorithm(t *testing.T) {
	der := selfSignedRSACertificate(t).Certificate[0]
	// sha256WithRSAEncryption, 1.2.840.113549.1.1.11, appears once in
	// tbsCertificate and once after it. The unnamed identifier is the same with
	// its last arc changed to 127.
	named := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}
	unnamed := append(slices.Clone(named[:len(named)-1]), 0x7F)
	if n := bytes.Count(der, named); n != 2 {
		t.Fatalf("certificate holds %d sha256WithRSAEncryption identifiers, want 2", n)
	}
	for _, test := range []struct {
		name string
		der  []byte
		want string
	}{
		{"named", der, "SHA256-RSA"},
		{"unnamed", bytes.ReplaceAll(der, named, unnamed), "1.2.840.113549.1.1.127"},
	} {
		t.Run(test.name, func(t *testing.T) {
			leaf, err := x509.ParseCertificate(test.der)
			if err != nil {
				t.Fatalf("ParseCertificate returned error: %v", err)
			}
			cert := summarizeCertificate("127.0.0.1", []*x509.Certificate{leaf}, nil, time.Now())
			if cert.SignatureAlgorithm != test.want {
				t.Errorf("SignatureAlgorithm = %q, want %q", cert.SignatureAlgorithm, test.want)
			}
		})
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

// A certificate is valid from notBefore through notAfter, inclusive (RFC 5280
// section 4.1.2.5).
func TestAssessCertificateValidityPeriodIncludesItsEnds(t *testing.T) {
	notAfter := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	notBefore := notAfter.Add(-90 * 24 * time.Hour)
	for _, test := range []struct {
		name    string
		now     time.Time
		expired bool
		valid   bool
	}{
		{"at not_before", notBefore, false, true},
		{"a second before not_after", notAfter.Add(-time.Second), false, true},
		{"at not_after", notAfter, false, true},
		{"a second after not_after", notAfter.Add(time.Second), true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			assessment := assess(EndpointResult{
				Reachable: ptr(true),
				TLS:       &TLSDetails{ProtocolSupport: ProtocolSupport{TLS12: ptr(true), TLS13: ptr(true)}},
				Certificate: &Certificate{
					NotBefore:     notBefore,
					NotAfter:      notAfter,
					ExpiresInDays: daysUntil(test.now, notAfter),
					TrustedChain:  true,
					HostnameValid: true,
				},
			}, test.now)
			if got := boolText(assessment.Expired); got != strconv.FormatBool(test.expired) {
				t.Errorf("Expired = %s, want %v", got, test.expired)
			}
			if got := boolText(assessment.CertificateValid); got != strconv.FormatBool(test.valid) {
				t.Errorf("CertificateValid = %s, want %v; issues: %v", got, test.valid, assessment.Issues)
			}
		})
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

// A server written before TLS 1.3 turns down a version it lacks by naming an
// older one in its ServerHello. That version reads false, with no gap.
func TestScanEndpointReadsAnOlderServerHelloAsTurnedDown(t *testing.T) {
	for _, test := range []struct {
		name      string
		version   uint16
		reachable bool
		modern    bool
		support   []bool // TLS 1.0, 1.1, 1.2 and 1.3
	}{
		{"TLS 1.2 only", tls.VersionTLS12, true, true, []bool{false, false, true, false}},
		{"TLS 1.0 only", tls.VersionTLS10, false, false, []bool{true, false, false, false}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, gaps := scanOne(preTLS13Server(t, test.version))
			if got := boolText(result.Reachable); got != strconv.FormatBool(test.reachable) {
				t.Errorf("Reachable = %s, want %v; errors: %v", got, test.reachable, result.Errors)
			}
			if got := boolText(result.Assessment.ModernProtocol); got != strconv.FormatBool(test.modern) {
				t.Errorf("ModernProtocol = %s, want %v", got, test.modern)
			}
			support := result.TLS.ProtocolSupport
			for i, got := range []*bool{support.TLS10, support.TLS11, support.TLS12, support.TLS13} {
				if boolText(got) != strconv.FormatBool(test.support[i]) {
					t.Errorf("%s support = %s, want %v", tlsVersionName(probes[i].version), boolText(got), test.support[i])
				}
			}
			if len(gaps) != 0 {
				t.Errorf("gaps = %+v, want none", gaps)
			}
		})
	}
}

// A server sets the version in its ServerHello and asks for a client
// certificate later (RFC 5246 sections 7.4.1.3 and 7.4.6). A server that
// requires a client certificate fails each handshake without one. It still
// supports each version it sets.
func TestScanEndpointAgainstAServerThatRequiresAClientCertificate(t *testing.T) {
	for _, test := range []struct {
		name       string
		minVersion uint16
		maxVersion uint16
		support    []bool // TLS 1.0, 1.1, 1.2 and 1.3
	}{
		{"TLS 1.0 only", tls.VersionTLS10, tls.VersionTLS10, []bool{true, false, false, false}},
		{"TLS 1.2 only", tls.VersionTLS12, tls.VersionTLS12, []bool{false, false, true, false}},
		{"TLS 1.2 and 1.3", tls.VersionTLS12, tls.VersionTLS13, []bool{false, false, true, true}},
	} {
		for _, clientAuth := range []tls.ClientAuthType{tls.NoClientCert, tls.RequireAnyClientCert} {
			t.Run(test.name+" with "+clientAuth.String(), func(t *testing.T) {
				result, gaps := scanOne(tlsServer(t, serverConfig(t, test.minVersion, test.maxVersion, clientAuth)))
				support := result.TLS.ProtocolSupport
				for i, got := range []*bool{support.TLS10, support.TLS11, support.TLS12, support.TLS13} {
					if boolText(got) != strconv.FormatBool(test.support[i]) {
						t.Errorf("%s support = %s, want %v; errors: %v", tlsVersionName(probes[i].version), boolText(got), test.support[i], result.Errors)
					}
				}
				legacy, modern := test.support[0] || test.support[1], test.support[2] || test.support[3]
				if got := boolText(result.Assessment.LegacyProtocolSupported); got != strconv.FormatBool(legacy) {
					t.Errorf("LegacyProtocolSupported = %s, want %v", got, legacy)
				}
				if got := boolText(result.Assessment.ModernProtocol); got != strconv.FormatBool(modern) {
					t.Errorf("ModernProtocol = %s, want %v", got, modern)
				}
				if len(gaps) != 0 {
					t.Errorf("gaps = %+v, want none", gaps)
				}
			})
		}
	}
}

// Only a handshake_failure or protocol_version alert in reply to a ClientHello
// turns down the versions it offers (RFC 5246 section 7.4.1.3 and RFC 8446
// section 6.2). Another alert leaves the values out with a gap.
func TestScanEndpointReadsOnlyAVersionAlertAsTurnedDown(t *testing.T) {
	for _, test := range []struct {
		name       string
		alert      byte
		turnedDown bool
	}{
		{"handshake_failure", 40, true},
		{"protocol_version", 70, true},
		{"internal_error", 80, false},
		{"unrecognized_name", 112, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, gaps := scanOne(alertServer(t, test.alert))
			want := "left out"
			if test.turnedDown {
				want = "false"
			}
			left := map[string]bool{}
			for _, g := range gaps {
				left[g.pointer] = true
			}
			if got := boolText(result.Reachable); got != want {
				t.Errorf("Reachable = %s, want %s; errors: %v", got, want, result.Errors)
			}
			if left["/reachable"] == test.turnedDown {
				t.Errorf("reachable gap recorded = %v, want %v", left["/reachable"], !test.turnedDown)
			}
			support := result.TLS.ProtocolSupport
			for i, got := range []*bool{support.TLS10, support.TLS11, support.TLS12, support.TLS13} {
				if boolText(got) != want {
					t.Errorf("%s support = %s, want %s", tlsVersionName(probes[i].version), boolText(got), want)
				}
				if pointer := "/tls/protocol_support/" + probes[i].field; left[pointer] == test.turnedDown {
					t.Errorf("%s gap recorded = %v, want %v", pointer, left[pointer], !test.turnedDown)
				}
			}
		})
	}
}

// A handshake that times out or is reset after the dial counts against its
// operation, with the code of the gaps it leaves. The run's call counts hold
// the tally, since a trust-level collector result leaves the counts out.
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
	if got := len(res.Operations); got != 1+len(probes) {
		t.Errorf("operations = %d, want the handshake and %d probes", got, len(probes))
	}
	for _, op := range res.Operations {
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

// tlsServer serves config on a loopback port and completes each handshake it
// can.
func tlsServer(t *testing.T, config *tls.Config) Endpoint {
	t.Helper()
	return localServer(t, func(conn net.Conn) {
		go func() {
			defer func() { _ = conn.Close() }()
			_ = tls.Server(conn, config).Handshake()
		}()
	})
}

// serverConfig accepts minVersion through maxVersion with a self-signed
// certificate. A server that accepts TLS 1.1 or older offers the one cipher
// suite the legacy tests use.
func serverConfig(t *testing.T, minVersion, maxVersion uint16, clientAuth tls.ClientAuthType) *tls.Config {
	t.Helper()
	config := &tls.Config{
		Certificates: []tls.Certificate{selfSignedRSACertificate(t)},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
		ClientAuth:   clientAuth,
	}
	if minVersion <= tls.VersionTLS11 {
		config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}
	}
	return config
}

// alertServer reads each ClientHello and answers it with a fatal alert with
// the number alert.
func alertServer(t *testing.T, alert byte) Endpoint {
	t.Helper()
	return localServer(t, func(conn net.Conn) {
		go func() {
			defer func() { _ = conn.Close() }()
			header := make([]byte, 5)
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}
			if _, err := io.ReadFull(conn, make([]byte, int(header[3])<<8|int(header[4]))); err != nil {
				return
			}
			_, _ = conn.Write([]byte{21, 3, 3, 0, 2, 2, alert})
		}()
	})
}

// preTLS13Server serves only version, as a server written before TLS 1.3
// does. It reads the ClientHello's legacy_version and ignores the
// supported_versions extension. When legacy_version is at least version, the
// server names version in its ServerHello (RFC 8446 appendix D.1). Otherwise
// it sends a protocol_version alert.
func preTLS13Server(t *testing.T, version uint16) Endpoint {
	t.Helper()
	cert := selfSignedRSACertificate(t)
	return localServer(t, func(conn net.Conn) {
		go func() {
			defer func() { _ = conn.Close() }()
			header := make([]byte, 5)
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}
			hello := make([]byte, int(header[3])<<8|int(header[4]))
			if _, err := io.ReadFull(conn, hello); err != nil {
				return
			}
			legacy, offered := clientHelloVersions(hello)
			switch {
			case legacy < version:
				_, _ = conn.Write([]byte{21, 3, 3, 0, 2, 2, 70})
			case !slices.Contains(offered, version):
				_, _ = conn.Write(serverHelloRecord(version))
				_, _ = io.Copy(io.Discard, conn)
			default:
				config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version}
				if version <= tls.VersionTLS11 {
					config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}
				}
				_ = tls.Server(&replayConn{Conn: conn, read: append(header, hello...)}, config).Handshake()
			}
		}()
	})
}

// clientHelloVersions returns a ClientHello message's legacy_version and the
// versions its supported_versions extension lists.
func clientHelloVersions(msg []byte) (legacy uint16, offered []uint16) {
	// type(1) length(3) legacy_version(2) random(32) session_id<1>
	// cipher_suites<2> compression_methods<1> extensions<2>
	legacy = uint16(msg[4])<<8 | uint16(msg[5])
	i := 4 + 2 + 32
	i += 1 + int(msg[i])
	i += 2 + (int(msg[i])<<8 | int(msg[i+1]))
	i += 1 + int(msg[i])
	extensions := msg[i+2 : i+2+(int(msg[i])<<8|int(msg[i+1]))]
	for len(extensions) >= 4 {
		size := int(extensions[2])<<8 | int(extensions[3])
		if extensions[0] == 0 && extensions[1] == 43 {
			for list := extensions[5 : 4+size]; len(list) >= 2; list = list[2:] {
				offered = append(offered, uint16(list[0])<<8|uint16(list[1]))
			}
		}
		extensions = extensions[4+size:]
	}
	return legacy, offered
}

// serverHelloRecord is a record holding a ServerHello for version, with the
// TLS_RSA_WITH_AES_128_CBC_SHA suite and no extensions.
func serverHelloRecord(version uint16) []byte {
	hello := append([]byte{byte(version >> 8), byte(version)}, make([]byte, 32)...)
	hello = append(hello, 0, 0x00, 0x2f, 0)
	message := append([]byte{2, 0, 0, byte(len(hello))}, hello...)
	return append([]byte{22, byte(version >> 8), byte(version), 0, byte(len(message))}, message...)
}

// replayConn returns the bytes in read before it reads from Conn.
type replayConn struct {
	net.Conn
	read []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.read) > 0 {
		n := copy(p, c.read)
		c.read = c.read[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// boolText is b as true or false, or "left out" when b is nil.
func boolText(b *bool) string {
	if b == nil {
		return "left out"
	}
	return strconv.FormatBool(*b)
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
