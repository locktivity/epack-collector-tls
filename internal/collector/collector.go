package collector

import (
	"context"
	"fmt"
	"time"
)

const defaultTimeout = 10 * time.Second

type EndpointScanner func(context.Context, Endpoint, time.Duration) EndpointResult

func Collect(ctx context.Context, cfg Config) (*TLSPosture, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	scanner := cfg.EndpointScanner
	if scanner == nil {
		scanner = ScanEndpoint
	}

	posture := &TLSPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		Endpoints:     make([]EndpointResult, 0, len(cfg.Endpoints)),
	}

	total := len(cfg.Endpoints)
	for i, endpoint := range cfg.Endpoints {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		message := fmt.Sprintf("Scanning %s:%d", endpoint.Host, endpoint.Port)
		if cfg.OnStatus != nil {
			cfg.OnStatus(message)
		}
		if cfg.OnProgress != nil {
			cfg.OnProgress(int64(i), int64(total), message)
		}

		result := scanner(ctx, endpoint, timeout)
		posture.Endpoints = append(posture.Endpoints, result)
	}

	if cfg.OnProgress != nil {
		cfg.OnProgress(int64(total), int64(total), "Collection complete")
	}

	posture.Summary = computeSummary(posture.Endpoints)
	posture.Diagnostics = computeDiagnostics(posture.Endpoints)
	return posture, nil
}

func computeSummary(endpoints []EndpointResult) Summary {
	total := len(endpoints)
	summary := Summary{TotalEndpoints: total}
	if total == 0 {
		return summary
	}

	var reachable, certValid, hostnameValid, modern, expiringSoon, legacy int
	for _, endpoint := range endpoints {
		if endpoint.Reachable {
			reachable++
		}
		if endpoint.Assessment.CertificateValid {
			certValid++
		}
		if endpoint.Assessment.HostnameValid {
			hostnameValid++
		}
		if endpoint.Assessment.ModernProtocol {
			modern++
		}
		if endpoint.Assessment.ExpiringSoon {
			expiringSoon++
		}
		if endpoint.Assessment.LegacyProtocolSupported {
			legacy++
		}
	}

	summary.ReachablePct = pct(reachable, total)
	summary.CertificateValidPct = pct(certValid, total)
	summary.HostnameValidPct = pct(hostnameValid, total)
	summary.ModernProtocolPct = pct(modern, total)
	summary.ExpiringSoonPct = pct(expiringSoon, total)
	summary.LegacyProtocolSupportedPct = pct(legacy, total)
	summary.AllCertificatesValid = certValid == total
	summary.AllModernProtocol = modern == total
	return summary
}

func computeDiagnostics(endpoints []EndpointResult) *Diagnostics {
	var endpointErrors []string
	for _, endpoint := range endpoints {
		for _, err := range endpoint.Errors {
			endpointErrors = append(endpointErrors, fmt.Sprintf("%s:%d: %s", endpoint.Host, endpoint.Port, err))
		}
	}
	if len(endpointErrors) == 0 {
		return nil
	}
	return &Diagnostics{EndpointErrors: endpointErrors}
}

func pct(count, total int) int {
	if total == 0 {
		return 0
	}
	return (count * 100) / total
}
