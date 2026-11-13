package collector

import (
	"cmp"
	"crypto/tls"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated endpoints are rosters the simulator serves, each with the
// values roster.Derive computes from it. A value the collector reports
// otherwise is listed with a verdict and a note that says where in the
// collector's code it was checked, so a new difference fails, and so does a
// listed one that goes away.

// simStanding are the differences every roster shows.
var simStanding = simulate.Differences{}

// simUncompared are the fields the collector writes that no scenario's
// roster gives a value for.
var simUncompared = map[string]string{
	"/endpoints/*/certificate/fingerprint_sha256":  "The certificate's bytes change each time the simulator signs it, so the roster can't fix its fingerprint.",
	"/endpoints/*/certificate/issuer_common_name":  simRenewed,
	"/endpoints/*/certificate/not_after":           simRenewed,
	"/endpoints/*/certificate/not_before":          simRenewed,
	"/endpoints/*/certificate/serial_number":       simRenewed,
	"/endpoints/*/certificate/signature_algorithm": simRenewed,
	"/endpoints/*/certificate/subject_common_name": simRenewed,
}

// simRenewed says why the sandbox roster leaves a certificate field out.
const simRenewed = "The sandbox's Let's Encrypt certificates change at each renewal, so its roster leaves this out. The every certificate field scenario compares it."

// simTLS13Suite is the difference a roster shows when its server picks a
// TLS 1.3 cipher suite crypto/tls doesn't, at each endpoint pointer.
func simTLS13Suite(endpoints ...int) simulate.Differences {
	var pointers []string
	for _, i := range endpoints {
		pointers = append(pointers, fmt.Sprintf("/endpoints/%d/tls/negotiated_cipher_suite", i))
	}
	return simulate.Same(simulate.Unmodeled,
		"crypto/tls picks the TLS 1.3 cipher suite itself, AES-128-GCM here, where the sandbox's nginx picks AES-256-GCM.", pointers...)
}

// simLegacyOnlyNote says why an endpoint that accepts only TLS 1.0 or 1.1
// differs.
const simLegacyOnlyNote = "connect reads the certificate and the negotiated version from a handshake that offers TLS 1.2 and up, which an endpoint that accepts only older versions turns down, so the collector reads none there. Derive takes them from the roster."

// simLegacyOnly is the difference an endpoint that accepts only TLS 1.0 or
// 1.1 shows at index i, and in the summary pointers given.
func simLegacyOnly(i int, summary ...string) simulate.Differences {
	at := fmt.Sprintf("/endpoints/%d", i)
	return simulate.Same(simulate.Definition, simLegacyOnlyNote, append([]string{
		at + "/certificate/chain_length", at + "/certificate/dns_names", at + "/certificate/expires_in_days", at + "/certificate/hostname_valid",
		at + "/certificate/ip_addresses", at + "/certificate/public_key_algorithm", at + "/certificate/trusted_chain",
		at + "/tls/negotiated_version", at + "/tls/negotiated_cipher_suite", at + "/assessment/certificate_valid", at + "/assessment/hostname_valid",
		"/summary/certificate_valid_count", "/summary/certificate_valid_pct", "/summary/hostname_valid_count", "/summary/hostname_valid_pct",
	}, summary...)...)
}

func simScenarios(t testing.TB) []simulate.Scenario {
	return []simulate.Scenario{
		{Name: "sandbox", Roster: simBase(t), Differences: simTLS13Suite(0, 1, 3, 4, 5).With(simLegacyOnly(2))},
		{Name: "every certificate field", Roster: simFullCertificate(t)},
	}
}

func TestSimulatedEndpoints(t *testing.T) {
	simHarness(simStanding).Tenants(t, simScenarios(t))
}

// simContractKnown lists the ways the sandbox roster is known to differ
// from the recording, with why.
var simContractKnown = map[string]string{}

// TestSimulatorMatchesRecording compares the sandbox roster with a
// recording of the sandbox, so the roster can't drift from the endpoints
// unseen: an endpoint whose versions, names, or trust differ from the ones
// recorded fails here, in the pull request that brings a new recording or
// roster. The recording's certificate dates move at each renewal, and the
// roster fixes one day inside each expectation's range instead, so they
// aren't compared.
func TestSimulatorMatchesRecording(t *testing.T) {
	recorded, err := collectortest.LoadScenario("testdata/recordings/tls.json")
	if err != nil {
		t.Fatal(err)
	}
	r := simBase(t)
	byAddress := map[string]collectortest.Endpoint{}
	for _, e := range recorded.Endpoints {
		byAddress[strings.ToLower(e.Address)] = e
	}
	var diffs []string
	for _, e := range r.Hosts.Endpoints {
		address := net.JoinHostPort(strings.ToLower(e.Host), strconv.Itoa(e.Port))
		rec, ok := byAddress[address]
		if !ok {
			diffs = append(diffs, address+": not recorded")
			continue
		}
		delete(byAddress, address)
		var accepts []uint16
		for vendor, term := range r.Terms.TLSVersions {
			if v, ok := simVersions[term]; ok && slices.Contains(e.Accepts, vendor) {
				accepts = append(accepts, v)
			}
		}
		slices.Sort(accepts)
		var served []uint16
		if !rec.Refused && !rec.Plaintext {
			for v := cmp.Or(rec.MinVersion, tls.VersionTLS12); v <= cmp.Or(rec.MaxVersion, tls.VersionTLS13); v++ {
				served = append(served, v)
			}
		}
		if !slices.Equal(accepts, served) {
			diffs = append(diffs, fmt.Sprintf("%s: the roster accepts %v, the recording serves %v", address, accepts, served))
		}
		if e.Certificate == nil {
			continue
		}
		if !slices.Equal(slices.Sorted(slices.Values(e.Certificate.DNSNames)), slices.Sorted(slices.Values(rec.Cert.DNSNames))) {
			diffs = append(diffs, address+": names differ")
		}
		trusted := e.Certificate.Root != "" && r.Terms.TLSRoots[e.Certificate.Root] == roster.TLSRootTrusted
		if trusted == rec.Cert.Untrusted {
			diffs = append(diffs, fmt.Sprintf("%s: the roster's root is trusted %v, the recording's certificate untrusted %v", address, trusted, rec.Cert.Untrusted))
		}
	}
	for address := range byAddress {
		diffs = append(diffs, address+": recorded, not in the roster")
	}
	seen := map[string]bool{}
	for _, d := range diffs {
		seen[d] = true
		if why, known := simContractKnown[d]; known {
			t.Logf("known: %s (%s)", d, why)
			continue
		}
		t.Errorf("%s", d)
	}
	for _, d := range slices.Sorted(maps.Keys(simContractKnown)) {
		if !seen[d] {
			t.Errorf("listed as known, but the roster now matches the recording: %s", d)
		}
	}
}
