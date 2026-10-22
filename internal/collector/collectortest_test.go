package collector

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

const (
	kitModern    = "modern.example.com:443"
	kitLegacy    = "legacy.example.com:443"
	kitExpired   = "expired.example.com:443"
	kitUntrusted = "untrusted.example.com:443"
	kitMismatch  = "mismatch.example.com:443"
	kitPlaintext = "plaintext.example.com:80"
	kitClosed    = "closed.example.com:443"

	kitResultPath = "artifacts/tls.collector-result.json"
)

var kitAddresses = []string{kitModern, kitLegacy, kitExpired, kitUntrusted, kitMismatch, kitPlaintext}

// kitSteps are a run's steps in order, with their titles.
var kitSteps = [][2]string{
	{stepHandshake, "Certificates and negotiated TLS"},
	{stepProtocolSupport, "Supported TLS versions"},
}

// kitStepPins pins the steps in order, and that there are no more.
func kitStepPins() map[string]any {
	pins := map[string]any{}
	for i, s := range kitSteps {
		pins[fmt.Sprintf("/steps/%d/name", i)] = s[0]
		pins[fmt.Sprintf("/steps/%d/title", i)] = s[1]
	}
	pins[fmt.Sprintf("/steps/%d", len(kitSteps))] = collectortest.Absent
	return pins
}

func kitConfig() map[string]any {
	endpoints := make([]any, 0, len(kitAddresses))
	for _, address := range kitAddresses {
		endpoints = append(endpoints, address)
	}
	return map[string]any{"endpoints": endpoints}
}

// kitIgnore keeps error text and issue lists out of the value comparison:
// they describe what failed, so a fault changes them by design.
func kitIgnore() map[string][]string {
	pointers := []string{"/diagnostics"}
	for i := range kitAddresses {
		pointers = append(pointers, fmt.Sprintf("/endpoints/%d/errors", i), fmt.Sprintf("/endpoints/%d/assessment/issues", i))
	}
	return map[string][]string{ArtifactPath: pointers}
}

func kitClean() collectortest.Scenario {
	return collectortest.Scenario{
		Name: "clean",
		Endpoints: []collectortest.Endpoint{
			{Address: kitModern},
			{Address: kitLegacy, MinVersion: tls.VersionTLS10},
			{Address: kitExpired, Cert: collectortest.Cert{NotAfter: -24 * time.Hour}},
			{Address: kitUntrusted, Cert: collectortest.Cert{Untrusted: true}},
			{Address: kitMismatch, Cert: collectortest.Cert{DNSNames: []string{"www.example.net"}}},
			{Address: kitPlaintext, Plaintext: true},
		},
		Expect: map[string]map[string]any{ArtifactPath: {
			"/endpoints/0/reachable":                            true,
			"/endpoints/0/tls/negotiated_version":               "TLS 1.3",
			"/endpoints/0/tls/protocol_support/tls_1_0":         false,
			"/endpoints/0/tls/protocol_support/tls_1_1":         false,
			"/endpoints/0/tls/protocol_support/tls_1_2":         true,
			"/endpoints/0/tls/protocol_support/tls_1_3":         true,
			"/endpoints/0/certificate/expires_in_days":          60,
			"/endpoints/0/assessment/certificate_valid":         true,
			"/endpoints/1/tls/protocol_support/tls_1_0":         true,
			"/endpoints/1/tls/protocol_support/tls_1_1":         true,
			"/endpoints/1/assessment/legacy_protocol_supported": true,
			"/endpoints/2/certificate/expires_in_days":          -1,
			"/endpoints/2/certificate/trusted_chain":            true,
			"/endpoints/2/assessment/expired":                   true,
			"/endpoints/2/assessment/certificate_valid":         false,
			"/endpoints/3/certificate/trusted_chain":            false,
			"/endpoints/3/assessment/hostname_valid":            true,
			"/endpoints/3/assessment/certificate_valid":         false,
			"/endpoints/4/certificate/trusted_chain":            true,
			"/endpoints/4/assessment/hostname_valid":            false,
			"/endpoints/4/assessment/certificate_valid":         false,
			"/endpoints/5/reachable":                            false,
			"/endpoints/5/certificate":                          nil,
			"/endpoints/5/tls/protocol_support/tls_1_2":         false,
			"/endpoints/5/tls/protocol_support/tls_1_3":         false,
			"/endpoints/5/assessment/certificate_valid":         false,
			"/summary/total_endpoints":                          6,
			"/summary/reachable_count":                          5,
			"/summary/reachable_pct":                            83,
			"/summary/certificate_valid_count":                  2,
			"/summary/certificate_valid_pct":                    33,
			"/summary/hostname_valid_count":                     4,
			"/summary/hostname_valid_pct":                       66,
			"/summary/modern_protocol_count":                    5,
			"/summary/modern_protocol_pct":                      83,
			"/summary/expiring_soon_count":                      0,
			"/summary/expiring_soon_pct":                        0,
			"/summary/legacy_protocol_supported_count":          1,
			"/summary/legacy_protocol_supported_pct":            16,
			"/summary/all_certificates_valid":                   false,
			"/summary/all_modern_protocol":                      false,
		}, kitResultPath: kitStepPins()},
	}
}

// kitNoneReachable answers every configured address with servers that turn a
// modern handshake down: two accept only TLS 1.0 or 1.1, and the rest speak
// no TLS.
func kitNoneReachable() collectortest.Scenario {
	return collectortest.Scenario{
		Name: "no reachable endpoint",
		Endpoints: []collectortest.Endpoint{
			{Address: kitModern, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11},
			{Address: kitLegacy, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10},
			{Address: kitExpired, Plaintext: true},
			{Address: kitUntrusted, Plaintext: true},
			{Address: kitMismatch, Plaintext: true},
			{Address: kitPlaintext, Plaintext: true},
		},
		Expect: map[string]map[string]any{ArtifactPath: {
			"/endpoints/0/reachable":                    false,
			"/endpoints/0/tls/protocol_support/tls_1_1": true,
			"/endpoints/0/tls/protocol_support/tls_1_2": false,
			"/endpoints/1/reachable":                    false,
			"/endpoints/1/tls/protocol_support/tls_1_0": true,
			"/endpoints/2/reachable":                    false,
			"/endpoints/3/reachable":                    false,
			"/endpoints/4/reachable":                    false,
			"/endpoints/5/reachable":                    false,
			"/summary/total_endpoints":                  6,
			"/summary/reachable_count":                  0,
			"/summary/reachable_pct":                    0,
			"/summary/certificate_valid_count":          0,
			"/summary/certificate_valid_pct":            0,
			"/summary/modern_protocol_count":            0,
			"/summary/modern_protocol_pct":              0,
			"/summary/legacy_protocol_supported_count":  2,
			"/summary/legacy_protocol_supported_pct":    33,
			"/summary/all_certificates_valid":           false,
			"/summary/all_modern_protocol":              false,
		}},
	}
}

// kitClosedPort puts a closed port beside a modern endpoint. The refused
// connection is an answer, so the closed endpoint reads as unreachable with
// nothing left out and is not probed, while the refusal still counts against
// tls.handshake in the collector result.
func kitClosedPort() collectortest.Scenario {
	return collectortest.Scenario{
		Name:   "closed port",
		Config: map[string]any{"endpoints": []any{kitClosed, kitModern}},
		Endpoints: []collectortest.Endpoint{
			{Address: kitClosed, Refused: true},
			{Address: kitModern},
		},
		Expect: map[string]map[string]any{
			ArtifactPath: {
				"/endpoints/0/reachable":                    false,
				"/endpoints/0/certificate":                  collectortest.Absent,
				"/endpoints/0/tls/protocol_support/tls_1_0": false,
				"/endpoints/0/tls/protocol_support/tls_1_1": false,
				"/endpoints/0/tls/protocol_support/tls_1_2": false,
				"/endpoints/0/tls/protocol_support/tls_1_3": false,
				"/endpoints/0/assessment/certificate_valid": false,
				"/endpoints/0/assessment/modern_protocol":   false,
				"/endpoints/1/reachable":                    true,
				"/endpoints/1/assessment/certificate_valid": true,
				"/summary/reachable_count":                  1,
				"/summary/reachable_pct":                    50,
				"/summary/certificate_valid_count":          1,
				"/summary/certificate_valid_pct":            50,
				"/summary/modern_protocol_count":            1,
				"/summary/modern_protocol_pct":              50,
				"/summary/all_certificates_valid":           false,
			},
			kitResultPath: {
				"/outcome/status":                         "collected",
				"/calls/operations/0/name":                handshakeOperation,
				"/calls/operations/0/calls":               2,
				"/calls/operations/0/errors/vendor_error": 1,
				"/calls/operations/1/name":                "tls.probe.tls10",
				"/calls/operations/1/calls":               1,
			},
		},
	}
}

// kitAllRefused pins what a refused handshake does at PositionAll, where it
// hits every endpoint: each reads as unreachable with every version false,
// none is probed, and nothing is left out. kitClosedPort covers one refused
// endpoint among others.
func kitAllRefused() map[string]map[string]any {
	pins := map[string]any{
		"/summary/reachable_count":                 0,
		"/summary/reachable_pct":                   0,
		"/summary/certificate_valid_count":         0,
		"/summary/certificate_valid_pct":           0,
		"/summary/modern_protocol_count":           0,
		"/summary/modern_protocol_pct":             0,
		"/summary/legacy_protocol_supported_count": 0,
		"/summary/legacy_protocol_supported_pct":   0,
		"/summary/all_certificates_valid":          false,
		"/summary/all_modern_protocol":             false,
	}
	for i := range kitAddresses {
		endpoint := fmt.Sprintf("/endpoints/%d", i)
		pins[endpoint+"/reachable"] = false
		pins[endpoint+"/certificate"] = collectortest.Absent
		for _, p := range probes {
			pins[endpoint+"/tls/protocol_support/"+p.field] = false
		}
		pins[endpoint+"/assessment/certificate_valid"] = false
		pins[endpoint+"/assessment/modern_protocol"] = false
		pins[endpoint+"/assessment/legacy_protocol_supported"] = false
	}
	return map[string]map[string]any{
		ArtifactPath: pins,
		kitResultPath: {
			"/outcome/status":                         "collected",
			"/calls/operations/0/name":                handshakeOperation,
			"/calls/operations/0/errors/vendor_error": len(kitAddresses),
			"/calls/operations/1":                     collectortest.Absent,
		},
	}
}

func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:      Spec("test", "collectortest"),
		Run:       Run,
		Config:    kitConfig(),
		Scenarios: append([]collectortest.Scenario{kitClean(), kitNoneReachable(), kitClosedPort()}, kitRecordings(t, "tls")...),
		Semantics: []collectortest.Semantic{{
			Operation: handshakeOperation,
			Fault:     "refused",
			Meaning:   "nothing listens on the port, so the endpoint is unreachable",
			Positions: []string{collectortest.PositionAll},
			Expect:    kitAllRefused(),
		}},
		Ignore:        kitIgnore(),
		Operations:    []string{handshakeOperation, "tls.probe.tls10", "tls.probe.tls11", "tls.probe.tls12", "tls.probe.tls13"},
		GapOperations: true,
	})
}

// kitRecordings loads the scenarios TestRecord in record_test.go records
// from sandboxes, and logs each one not recorded yet.
func kitRecordings(t *testing.T, names ...string) []collectortest.Scenario {
	t.Helper()
	var out []collectortest.Scenario
	for _, name := range names {
		path := filepath.Join("testdata", "recordings", name+".json")
		sc, err := collectortest.LoadScenario(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			t.Logf("no recording at %s yet", path)
		case err != nil:
			t.Fatal(err)
		default:
			out = append(out, sc)
		}
	}
	return out
}
