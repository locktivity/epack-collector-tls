package collector

import (
	"context"
	"testing"
	"time"
)

func TestCollectUsesConfiguredScanner(t *testing.T) {
	endpoint, err := NewEndpoint("app.example.com", 443)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}

	var statusCalls []string
	var progressCalls []struct{ current, total int64 }
	posture, err := Collect(context.Background(), Config{
		Endpoints: []Endpoint{endpoint},
		EndpointScanner: func(_ context.Context, endpoint Endpoint, _ time.Duration) EndpointResult {
			return EndpointResult{
				Host:      endpoint.Host,
				Port:      endpoint.Port,
				Reachable: true,
				TLS: &TLSDetails{ProtocolSupport: ProtocolSupport{
					TLS12: true,
				}},
				Certificate: &Certificate{
					NotAfter:      time.Now().Add(90 * 24 * time.Hour),
					TrustedChain:  true,
					HostnameValid: true,
				},
				Assessment: Assessment{
					CertificateValid: true,
					HostnameValid:    true,
					ModernProtocol:   true,
				},
			}
		},
		OnStatus: func(message string) {
			statusCalls = append(statusCalls, message)
		},
		OnProgress: func(current int64, total int64, _ string) {
			progressCalls = append(progressCalls, struct{ current, total int64 }{current, total})
		},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if posture.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", posture.SchemaVersion, SchemaVersion)
	}
	if len(posture.Endpoints) != 1 {
		t.Fatalf("len(Endpoints) = %d, want 1", len(posture.Endpoints))
	}
	if posture.Summary.ReachablePct != 100 {
		t.Errorf("ReachablePct = %d, want 100", posture.Summary.ReachablePct)
	}
	if posture.Diagnostics != nil {
		t.Errorf("Diagnostics = %+v, want nil", posture.Diagnostics)
	}
	if len(statusCalls) != 1 {
		t.Errorf("len(statusCalls) = %d, want 1", len(statusCalls))
	}
	if len(progressCalls) != 2 {
		t.Errorf("len(progressCalls) = %d, want 2", len(progressCalls))
	}
}

func TestComputeSummary(t *testing.T) {
	endpoints := []EndpointResult{
		{
			Reachable: true,
			Assessment: Assessment{
				CertificateValid: true,
				HostnameValid:    true,
				ModernProtocol:   true,
			},
		},
		{
			Reachable: true,
			Assessment: Assessment{
				ExpiringSoon:            true,
				LegacyProtocolSupported: true,
			},
		},
	}

	summary := computeSummary(endpoints)
	if summary.TotalEndpoints != 2 {
		t.Errorf("TotalEndpoints = %d, want 2", summary.TotalEndpoints)
	}
	if summary.ReachablePct != 100 {
		t.Errorf("ReachablePct = %d, want 100", summary.ReachablePct)
	}
	if summary.CertificateValidPct != 50 {
		t.Errorf("CertificateValidPct = %d, want 50", summary.CertificateValidPct)
	}
	if summary.ExpiringSoonPct != 50 {
		t.Errorf("ExpiringSoonPct = %d, want 50", summary.ExpiringSoonPct)
	}
	if summary.LegacyProtocolSupportedPct != 50 {
		t.Errorf("LegacyProtocolSupportedPct = %d, want 50", summary.LegacyProtocolSupportedPct)
	}
	if summary.AllCertificatesValid {
		t.Error("AllCertificatesValid = true, want false")
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
