package collector

import (
	"context"
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
