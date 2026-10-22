package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const defaultTimeout = 10 * time.Second

// Steps of a run, in order. Each makes one kind of handshake with every
// endpoint.
const (
	stepHandshake       = "handshake"
	stepProtocolSupport = "protocol_support"
)

// Collect scans the endpoints in the run's steps. It always returns a
// posture: a value it cannot read is left out, with a gap in cfg.Recorder.
func Collect(ctx context.Context, cfg Config) *TLSPosture {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	s := scanner{dial: cfg.Dial, roots: cfg.RootCAs, timeout: timeout, progress: cfg.OnProgress}

	posture := &TLSPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   cfg.Now().UTC(),
		Endpoints:     make([]EndpointResult, 0, len(cfg.Endpoints)),
	}
	scans := make([]endpointScan, len(cfg.Endpoints))
	for i, endpoint := range cfg.Endpoints {
		scans[i] = newEndpointScan(i, endpoint, cfg.Recorder)
	}

	s.step(ctx, stepHandshake, "Certificates and negotiated TLS", scans, func(ctx context.Context, e *endpointScan) {
		e.now = cfg.Now()
		s.connect(ctx, e)
	})
	s.step(ctx, stepProtocolSupport, "Supported TLS versions", scans, s.probe)

	endpointGaps := make([][]gap, 0, len(scans))
	for i := range scans {
		scans[i].assess()
		posture.Endpoints = append(posture.Endpoints, scans[i].result)
		endpointGaps = append(endpointGaps, scans[i].gaps)
	}
	if cfg.OnProgress != nil {
		cfg.OnProgress(int64(len(scans)), int64(len(scans)), "Collection complete")
	}

	posture.Summary = computeSummary(posture.Endpoints, endpointGaps, cfg.Recorder)
	posture.Diagnostics = computeDiagnostics(posture.Endpoints)
	return posture
}

// step runs scan on every endpoint as the run's step named name.
func (s scanner) step(ctx context.Context, name, title string, scans []endpointScan, scan func(context.Context, *endpointScan)) {
	ctx, step := componentsdk.StartStep(ctx, name, title)
	defer step.End()
	for i := range scans {
		if s.progress != nil {
			endpoint := scans[i].endpoint
			s.progress(int64(i), int64(len(scans)), fmt.Sprintf("%s: %s:%d", title, endpoint.Host, endpoint.Port))
		}
		scan(ctx, &scans[i])
	}
}

func location(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: ArtifactPath, Pointer: pointer}
}

// computeSummary rolls the endpoints up. A count or percentage over
// endpoints with a value left out is left out too, with a partial gap, and so
// is an every-endpoint flag unless a read value already makes it false.
func computeSummary(endpoints []EndpointResult, gaps [][]gap, rec *componentsdk.Recorder) Summary {
	total := len(endpoints)
	ratio := func(field string, t tally) (*int, *int) {
		rec.Helper()
		if t.unknown > 0 {
			rec.Partial(location("/summary/"+field+"_count"), t.unknown, t.err)
			rec.Partial(location("/summary/"+field+"_pct"), t.unknown, t.err)
			return nil, nil
		}
		return ptr(t.matching), ptr((t.matching * 100) / total)
	}
	every := func(pointer string, t tally) *bool {
		rec.Helper()
		switch {
		case t.matching+t.unknown < total:
			return ptr(false)
		case t.unknown > 0:
			rec.Partial(location(pointer), t.unknown, t.err)
			return nil
		default:
			return ptr(true)
		}
	}

	reachable := count(endpoints, gaps, "/reachable", func(e EndpointResult) *bool { return e.Reachable })
	certValid := count(endpoints, gaps, "/assessment/certificate_valid", func(e EndpointResult) *bool { return e.Assessment.CertificateValid })
	hostnameValid := count(endpoints, gaps, "/assessment/hostname_valid", func(e EndpointResult) *bool { return e.Assessment.HostnameValid })
	modern := count(endpoints, gaps, "/assessment/modern_protocol", func(e EndpointResult) *bool { return e.Assessment.ModernProtocol })
	expiringSoon := count(endpoints, gaps, "/assessment/expiring_soon", func(e EndpointResult) *bool { return e.Assessment.ExpiringSoon })
	legacy := count(endpoints, gaps, "/assessment/legacy_protocol_supported", func(e EndpointResult) *bool { return e.Assessment.LegacyProtocolSupported })

	summary := Summary{TotalEndpoints: total}
	summary.ReachableCount, summary.ReachablePct = ratio("reachable", reachable)
	summary.CertificateValidCount, summary.CertificateValidPct = ratio("certificate_valid", certValid)
	summary.HostnameValidCount, summary.HostnameValidPct = ratio("hostname_valid", hostnameValid)
	summary.ModernProtocolCount, summary.ModernProtocolPct = ratio("modern_protocol", modern)
	summary.ExpiringSoonCount, summary.ExpiringSoonPct = ratio("expiring_soon", expiringSoon)
	summary.LegacyProtocolSupportedCount, summary.LegacyProtocolSupportedPct = ratio("legacy_protocol_supported", legacy)
	summary.AllCertificatesValid = every("/summary/all_certificates_valid", certValid)
	summary.AllModernProtocol = every("/summary/all_modern_protocol", modern)
	return summary
}

// tally counts the endpoints whose value is true and those whose value was
// left out, keeping the first error that left one out.
type tally struct {
	matching int
	unknown  int
	err      error
}

func count(endpoints []EndpointResult, gaps [][]gap, pointer string, value func(EndpointResult) *bool) tally {
	var t tally
	for i, endpoint := range endpoints {
		v := value(endpoint)
		switch {
		case v == nil:
			t.unknown++
			if t.err == nil {
				t.err = gapError(gaps[i], pointer)
			}
		case *v:
			t.matching++
		}
	}
	return t
}

func gapError(gaps []gap, pointer string) error {
	for _, g := range gaps {
		if g.pointer == pointer {
			return g.err
		}
	}
	return nil
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
