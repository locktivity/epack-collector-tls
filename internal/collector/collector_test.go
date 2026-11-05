package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

func TestCollectReadsAClosedPortOrAnUnknownHostAsUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	_, portString, _ := net.SplitHostPort(listener.Addr().String())
	_ = listener.Close()
	port, _ := strconv.Atoi(portString)
	closed, err := NewEndpoint("127.0.0.1", port)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}
	gone, err := NewEndpoint("gone.example.com", 443)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}

	var dialer net.Dialer
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "gone.example.com:443" {
			return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "no such host", Name: "gone.example.com", IsNotFound: true}}
		}
		return dialer.DialContext(ctx, network, address)
	}
	rec := &componentsdk.Recorder{}
	var progressCalls []struct{ current, total int64 }
	posture := Collect(context.Background(), Config{
		Endpoints: []Endpoint{closed, gone},
		Dial:      dial,
		Now:       time.Now,
		Recorder:  rec,
		OnProgress: func(current int64, total int64, _ string) {
			progressCalls = append(progressCalls, struct{ current, total int64 }{current, total})
		},
	})

	if posture.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", posture.SchemaVersion, SchemaVersion)
	}
	if len(posture.Endpoints) != 2 {
		t.Fatalf("len(Endpoints) = %d, want 2", len(posture.Endpoints))
	}
	for _, result := range posture.Endpoints {
		if result.Reachable == nil || *result.Reachable {
			t.Errorf("%s: Reachable = %v, want false; errors: %v", result.Host, result.Reachable, result.Errors)
		}
		support := result.TLS.ProtocolSupport
		for name, supported := range map[string]*bool{"TLS 1.0": support.TLS10, "TLS 1.1": support.TLS11, "TLS 1.2": support.TLS12, "TLS 1.3": support.TLS13} {
			if supported == nil || *supported {
				t.Errorf("%s: %s support = %v, want false", result.Host, name, supported)
			}
		}
		if result.Assessment.CertificateValid == nil || *result.Assessment.CertificateValid {
			t.Errorf("%s: CertificateValid = %v, want false", result.Host, result.Assessment.CertificateValid)
		}
	}
	if posture.Summary.ReachablePct == nil || *posture.Summary.ReachablePct != 0 {
		t.Errorf("ReachablePct = %v, want 0", posture.Summary.ReachablePct)
	}
	if gaps := rec.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none: a refused connection and an unknown host are answers", gaps)
	}
	if posture.Diagnostics == nil || len(posture.Diagnostics.EndpointErrors) != 2 {
		t.Errorf("Diagnostics = %+v, want both failed handshakes", posture.Diagnostics)
	}
	if len(progressCalls) != 5 {
		t.Errorf("len(progressCalls) = %d, want 5: each endpoint in both steps, then the end", len(progressCalls))
	}
}

// A TLS 1.0-only server written before TLS 1.3 answers the modern handshake
// with a TLS 1.0 ServerHello. It counts as unreachable over modern TLS in the
// summary, and nothing is left out.
func TestCollectSummarizesAServerWrittenBeforeTLS13(t *testing.T) {
	var dialer net.Dialer
	rec := &componentsdk.Recorder{}
	posture := Collect(context.Background(), Config{
		Endpoints: []Endpoint{preTLS13Server(t, tls.VersionTLS10), preTLS13Server(t, tls.VersionTLS12)},
		Dial:      dialer.DialContext,
		Now:       time.Now,
		Recorder:  rec,
	})

	s := posture.Summary
	if got := boolText(s.AllModernProtocol); got != "false" {
		t.Errorf("AllModernProtocol = %s, want false", got)
	}
	for name, got := range map[string]*int{
		"ReachablePct":               s.ReachablePct,
		"ModernProtocolPct":          s.ModernProtocolPct,
		"LegacyProtocolSupportedPct": s.LegacyProtocolSupportedPct,
	} {
		switch {
		case got == nil:
			t.Errorf("%s left out, want 50", name)
		case *got != 50:
			t.Errorf("%s = %d, want 50", name, *got)
		}
	}
	if gaps := rec.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none", gaps)
	}
}

// A server that requires a client certificate counts toward the versions it
// sets in its ServerHello, though each handshake without a client certificate
// fails.
func TestCollectSummarizesAServerThatRequiresAClientCertificate(t *testing.T) {
	var dialer net.Dialer
	rec := &componentsdk.Recorder{}
	posture := Collect(context.Background(), Config{
		Endpoints: []Endpoint{
			tlsServer(t, serverConfig(t, tls.VersionTLS12, tls.VersionTLS12, tls.RequireAnyClientCert)),
			tlsServer(t, serverConfig(t, tls.VersionTLS10, tls.VersionTLS10, tls.RequireAnyClientCert)),
		},
		Dial:     dialer.DialContext,
		Now:      time.Now,
		Recorder: rec,
	})

	s := posture.Summary
	for name, got := range map[string]*int{
		"ModernProtocolCount":          s.ModernProtocolCount,
		"LegacyProtocolSupportedCount": s.LegacyProtocolSupportedCount,
	} {
		switch {
		case got == nil:
			t.Errorf("%s left out, want 1", name)
		case *got != 1:
			t.Errorf("%s = %d, want 1", name, *got)
		}
	}
	for name, got := range map[string]*int{
		"ModernProtocolPct":          s.ModernProtocolPct,
		"LegacyProtocolSupportedPct": s.LegacyProtocolSupportedPct,
	} {
		switch {
		case got == nil:
			t.Errorf("%s left out, want 50", name)
		case *got != 50:
			t.Errorf("%s = %d, want 50", name, *got)
		}
	}
	if gaps := rec.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none", gaps)
	}
}

// A certificate is still valid in the second of its notAfter (RFC 5280
// section 4.1.2.5). crypto/x509 reads the chain the same way.
func TestCollectReadsACertificateAsValidAtItsNotAfter(t *testing.T) {
	config := serverConfig(t, tls.VersionTLS13, tls.VersionTLS13, tls.NoClientCert)
	leaf, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate returned error: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	endpoint := tlsServer(t, config)

	for _, test := range []struct {
		name  string
		now   time.Time
		valid bool
	}{
		{"a second before notAfter", leaf.NotAfter.Add(-time.Second), true},
		{"at notAfter", leaf.NotAfter, true},
		{"a second after notAfter", leaf.NotAfter.Add(time.Second), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var dialer net.Dialer
			posture := Collect(context.Background(), Config{
				Endpoints: []Endpoint{endpoint},
				Dial:      dialer.DialContext,
				RootCAs:   roots,
				Now:       func() time.Time { return test.now },
				Recorder:  &componentsdk.Recorder{},
			})
			assessment := posture.Endpoints[0].Assessment
			if got := boolText(assessment.Expired); got != strconv.FormatBool(!test.valid) {
				t.Errorf("Expired = %s, want %v", got, !test.valid)
			}
			if got := boolText(assessment.CertificateValid); got != strconv.FormatBool(test.valid) {
				t.Errorf("CertificateValid = %s, want %v; issues: %v", got, test.valid, assessment.Issues)
			}
			if got := boolText(posture.Summary.AllCertificatesValid); got != strconv.FormatBool(test.valid) {
				t.Errorf("AllCertificatesValid = %s, want %v", got, test.valid)
			}
		})
	}
}

func TestComputeSummary(t *testing.T) {
	endpoints := []EndpointResult{
		{
			Reachable: ptr(true),
			Assessment: Assessment{
				CertificateValid:        ptr(true),
				HostnameValid:           ptr(true),
				ExpiringSoon:            ptr(false),
				ModernProtocol:          ptr(true),
				LegacyProtocolSupported: ptr(false),
			},
		},
		{
			Reachable: ptr(true),
			Assessment: Assessment{
				CertificateValid:        ptr(false),
				HostnameValid:           ptr(false),
				ExpiringSoon:            ptr(true),
				ModernProtocol:          ptr(true),
				LegacyProtocolSupported: ptr(true),
			},
		},
	}

	rec := &componentsdk.Recorder{}
	summary := computeSummary(endpoints, make([][]gap, len(endpoints)), rec)
	if summary.TotalEndpoints != 2 {
		t.Errorf("TotalEndpoints = %d, want 2", summary.TotalEndpoints)
	}
	for _, check := range []struct {
		name string
		got  *int
		want int
	}{
		{"ReachableCount", summary.ReachableCount, 2},
		{"ReachablePct", summary.ReachablePct, 100},
		{"CertificateValidCount", summary.CertificateValidCount, 1},
		{"CertificateValidPct", summary.CertificateValidPct, 50},
		{"HostnameValidCount", summary.HostnameValidCount, 1},
		{"ModernProtocolCount", summary.ModernProtocolCount, 2},
		{"ExpiringSoonCount", summary.ExpiringSoonCount, 1},
		{"ExpiringSoonPct", summary.ExpiringSoonPct, 50},
		{"LegacyProtocolSupportedCount", summary.LegacyProtocolSupportedCount, 1},
		{"LegacyProtocolSupportedPct", summary.LegacyProtocolSupportedPct, 50},
	} {
		if check.got == nil || *check.got != check.want {
			t.Errorf("%s = %v, want %d", check.name, check.got, check.want)
		}
	}
	if summary.AllCertificatesValid == nil || *summary.AllCertificatesValid {
		t.Errorf("AllCertificatesValid = %v, want false", summary.AllCertificatesValid)
	}
	if gaps := rec.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none", gaps)
	}
}

func TestComputeSummaryLeavesOutRollupsOverValuesLeftOut(t *testing.T) {
	timeout := context.DeadlineExceeded
	read := Assessment{
		CertificateValid:        ptr(false),
		HostnameValid:           ptr(true),
		ExpiringSoon:            ptr(false),
		ModernProtocol:          ptr(true),
		LegacyProtocolSupported: ptr(false),
	}
	partlyRead := read
	partlyRead.CertificateValid = nil
	endpoints := []EndpointResult{
		{Reachable: ptr(true), Assessment: read},
		{Assessment: partlyRead},
	}
	gaps := [][]gap{nil, {
		{pointer: "/reachable", err: timeout},
		{pointer: "/assessment/certificate_valid", err: timeout},
	}}

	rec := &componentsdk.Recorder{}
	summary := computeSummary(endpoints, gaps, rec)
	if summary.ReachableCount != nil || summary.ReachablePct != nil || summary.CertificateValidCount != nil || summary.CertificateValidPct != nil {
		t.Errorf("reachable %v and %v%%, certificate valid %v and %v%%, want all left out",
			summary.ReachableCount, summary.ReachablePct, summary.CertificateValidCount, summary.CertificateValidPct)
	}
	if summary.AllCertificatesValid == nil || *summary.AllCertificatesValid {
		t.Errorf("AllCertificatesValid = %v, want false: one endpoint was read as invalid", summary.AllCertificatesValid)
	}
	if summary.ModernProtocolCount == nil || *summary.ModernProtocolCount != 2 || summary.ModernProtocolPct == nil || *summary.ModernProtocolPct != 100 {
		t.Errorf("ModernProtocolCount = %v, ModernProtocolPct = %v, want 2 and 100", summary.ModernProtocolCount, summary.ModernProtocolPct)
	}

	partial := map[string]componentsdk.Gap{}
	for _, g := range rec.Gaps() {
		partial[g.Pointer] = g
	}
	left := []string{"/summary/reachable_count", "/summary/reachable_pct", "/summary/certificate_valid_count", "/summary/certificate_valid_pct"}
	for _, pointer := range left {
		g, ok := partial[pointer]
		if !ok || g.Status != componentsdk.GapPartial || g.Unmeasured != 1 || g.Code != componentsdk.CodeTimeout {
			t.Errorf("gap at %s = %+v, want partial with 1 unmeasured and code timeout", pointer, g)
		}
	}
	if len(partial) != len(left) {
		t.Errorf("gaps = %+v, want only the two counts and their percentages", rec.Gaps())
	}
}

func TestComputeSummaryLeavesOutAnAllFlagAValueLeftOutCouldMakeFalse(t *testing.T) {
	valid := Assessment{
		CertificateValid:        ptr(true),
		HostnameValid:           ptr(true),
		ExpiringSoon:            ptr(false),
		ModernProtocol:          ptr(true),
		LegacyProtocolSupported: ptr(false),
	}
	unread := valid
	unread.CertificateValid = nil
	endpoints := []EndpointResult{
		{Reachable: ptr(true), Assessment: valid},
		{Reachable: ptr(true), Assessment: unread},
	}
	gaps := [][]gap{nil, {{pointer: "/assessment/certificate_valid", err: context.DeadlineExceeded}}}

	rec := &componentsdk.Recorder{}
	summary := computeSummary(endpoints, gaps, rec)
	if summary.AllCertificatesValid != nil {
		t.Errorf("AllCertificatesValid = %v, want it left out: every endpoint that was read is valid", *summary.AllCertificatesValid)
	}
	if summary.AllModernProtocol == nil || !*summary.AllModernProtocol {
		t.Errorf("AllModernProtocol = %v, want true", summary.AllModernProtocol)
	}
	var flagged bool
	for _, g := range rec.Gaps() {
		if g.Pointer == "/summary/all_certificates_valid" {
			flagged = g.Status == componentsdk.GapPartial && g.Unmeasured == 1 && g.Code == componentsdk.CodeTimeout
		}
	}
	if !flagged {
		t.Errorf("gaps = %+v, want a partial gap with 1 unmeasured and code timeout at /summary/all_certificates_valid", rec.Gaps())
	}
}

func TestComputeDiagnostics(t *testing.T) {
	diagnostics := computeDiagnostics([]EndpointResult{
		{Host: "app.example.com", Port: 443, Errors: []string{"TLS handshake failed"}},
	})
	if diagnostics == nil {
		t.Fatal("Diagnostics = nil, want endpoint error")
	}
	if got := diagnostics.EndpointErrors[0]; got != "app.example.com:443: TLS handshake failed" {
		t.Errorf("EndpointErrors[0] = %q", got)
	}
}
