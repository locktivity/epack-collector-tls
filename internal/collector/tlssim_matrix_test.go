package collector

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated matrix varies one endpoint along the axes below. Each
// one-at-a-time row changes one setting, so a difference it shows belongs to
// that setting and is listed in simMatrixAlone. The pairwise rows put every
// two settings together at least once, and a difference none of a row's
// settings shows alone must be listed in simMatrixTogether.

const (
	simMatrixHost         = "matrix.example.com"
	simMatrixIntermediate = "Simulated Intermediate"
	simMatrixRoot         = "Simulated Root"
	simMatrixOtherRoot    = "Simulated Untrusted Root"
)

// simMatrixBase is one endpoint that does everything right: it accepts TLS
// 1.2 and 1.3 and presents a certificate for its name, 60 days from expiry,
// that chains to a trusted root through one intermediate. The TLS 1.3 suite
// is the one crypto/tls picks.
func simMatrixBase(t testing.TB) *roster.Roster {
	t.Helper()
	r := simBase(t)
	r.Hosts = &roster.Hosts{Endpoints: []roster.TLSEndpoint{{
		Host:        simMatrixHost,
		Port:        443,
		Accepts:     []string{"TLSv1.2", "TLSv1.3"},
		Version:     "TLSv1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		Certificate: &roster.TLSCertificate{
			ExpiresInDays:      60,
			DNSNames:           []string{simMatrixHost},
			PublicKeyAlgorithm: "ECDSA",
			Chain:              []string{simMatrixHost, simMatrixIntermediate},
			Root:               simMatrixRoot,
		},
	}}}
	r.Terms.TLSRoots = map[string]string{
		simMatrixRoot:      roster.TLSRootTrusted,
		simMatrixOtherRoot: roster.TLSRootUntrusted,
		simMatrixHost:      roster.TLSRootUntrusted,
	}
	return r
}

// simFullCertificate is the matrix base with every certificate field the
// roster can fix in advance, so the scenarios compare each of them.
func simFullCertificate(t testing.TB) *roster.Roster {
	t.Helper()
	r := simMatrixBase(t)
	c := r.Hosts.Endpoints[0].Certificate
	c.SubjectCommonName, c.IssuerCommonName = simMatrixHost, simMatrixIntermediate
	c.SerialNumber, c.SignatureAlgorithm = "1234567890", "ECDSA-SHA256"
	c.NotBefore, c.NotAfter = "2025-12-01T00:00:00Z", "2026-03-03T00:00:00Z"
	validFrom := 31
	c.ValidFromDaysAgo = &validFrom
	c.IPAddresses = []string{"192.0.2.10"}
	return r
}

// onEndpoint changes the matrix endpoint, with a certificate of its own so
// a change to it leaves the base's alone.
func onEndpoint(change func(*roster.TLSEndpoint)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		e := &r.Hosts.Endpoints[0]
		if e.Certificate != nil {
			c := *e.Certificate
			e.Certificate = &c
		}
		change(e)
	}
}

// onCertificate changes the matrix endpoint's certificate, when it presents
// one.
func onCertificate(change func(*roster.TLSCertificate)) func(*roster.Roster) {
	return onEndpoint(func(e *roster.TLSEndpoint) {
		if e.Certificate != nil {
			change(e.Certificate)
		}
	})
}

func versions(version, suite string, accepts ...string) func(*roster.Roster) {
	return onEndpoint(func(e *roster.TLSEndpoint) {
		e.Accepts, e.Version, e.CipherSuite = accepts, version, suite
		if len(accepts) == 0 {
			e.Certificate = nil
		}
	})
}

func names(dnsNames ...string) func(*roster.Roster) {
	return onCertificate(func(c *roster.TLSCertificate) { c.DNSNames = dnsNames })
}

func expiresIn(days int) func(*roster.Roster) {
	return onCertificate(func(c *roster.TLSCertificate) { c.ExpiresInDays = days })
}

func simMatrixAxes() []roster.Axis {
	const ecdsaGCM, ecdsaCBC = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	return []roster.Axis{
		{Name: "versions", Values: []roster.Value{
			{Name: "modern"},
			{Name: "tls13_only", Change: versions("TLSv1.3", "TLS_AES_128_GCM_SHA256", "TLSv1.3")},
			{Name: "tls12_only", Change: versions("TLSv1.2", ecdsaGCM, "TLSv1.2")},
			{Name: "all", Change: versions("TLSv1.3", "TLS_AES_128_GCM_SHA256", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")},
			{Name: "legacy_only", Change: versions("TLSv1.1", ecdsaCBC, "TLSv1", "TLSv1.1")},
			{Name: "tls10_only", Change: versions("TLSv1", ecdsaCBC, "TLSv1")},
			{Name: "tls10_and_13", Change: versions("TLSv1.3", "TLS_AES_128_GCM_SHA256", "TLSv1", "TLSv1.3")},
			{Name: "none", Change: versions("", "")},
		}},
		{Name: "names", Values: []roster.Value{
			{Name: "own"},
			{Name: "wildcard", Change: names("*.example.com")},
			{Name: "other", Change: names("other.example.com")},
			{Name: "two", Change: names("other.example.com", simMatrixHost)},
			{Name: "two_wildcards", Change: names("*.*.example.com")},
			{Name: "upper_case", Change: names(strings.ToUpper(simMatrixHost))},
			{Name: "none", Change: names()},
		}},
		{Name: "expiry", Values: []roster.Value{
			{Name: "60_days"},
			{Name: "30_days", Change: expiresIn(30)},
			{Name: "29_days", Change: expiresIn(29)},
			{Name: "today", Change: expiresIn(0)},
			{Name: "yesterday", Change: expiresIn(-1)},
			{Name: "not_yet_valid", Change: onCertificate(func(c *roster.TLSCertificate) {
				days := -1
				c.ValidFromDaysAgo = &days
			})},
		}},
		{Name: "trust", Values: []roster.Value{
			{Name: "chained"},
			{Name: "self_signed", Change: onCertificate(func(c *roster.TLSCertificate) { c.Chain, c.Root = []string{simMatrixHost}, simMatrixHost })},
			{Name: "untrusted_root", Change: onCertificate(func(c *roster.TLSCertificate) { c.Root = simMatrixOtherRoot })},
			{Name: "missing_issuer", Change: onCertificate(func(c *roster.TLSCertificate) { c.Root = "" })},
			{Name: "long_chain", Change: onCertificate(func(c *roster.TLSCertificate) {
				c.Chain = []string{simMatrixHost, simMatrixIntermediate, "Simulated Cross-Signed Root"}
			})},
		}},
		{Name: "key", Values: []roster.Value{
			{Name: "ecdsa"},
			{Name: "rsa", Change: onEndpoint(func(e *roster.TLSEndpoint) {
				e.CipherSuite = strings.Replace(e.CipherSuite, "ECDHE_ECDSA", "ECDHE_RSA", 1)
				if e.Certificate != nil {
					e.Certificate.PublicKeyAlgorithm = "RSA"
				}
			})},
		}},
	}
}

// simMatrixAlone lists, by axis=value, the differences a setting shows on
// its own.
var simMatrixAlone = map[string]simulate.Differences{
	"versions=legacy_only": simLegacyOnly(0, "/summary/all_certificates_valid"),
	"versions=tls10_only":  simLegacyOnly(0, "/summary/all_certificates_valid"),
	"versions=none": simulate.Same(simulate.Unmodeled,
		"The roster leaves an endpoint's certificate out, or null, when the server completes no handshake. Derive writes null, and connect leaves it out when the connection is refused.",
		"/endpoints/0/certificate"),
}

// simMatrixTogether lists the differences settings show only together: a
// legacy-only endpoint's certificate, which the collector doesn't read,
// expired or about to.
var simMatrixTogether = []simulate.Together{
	{
		Match: func(choices []string) bool {
			return simulate.Any(choices, "versions=legacy_only", "versions=tls10_only") && simulate.Any(choices, "expiry=yesterday")
		},
		Differences: simulate.Same(simulate.Definition, simLegacyOnlyNote, "/endpoints/0/assessment/expired"),
	},
	{
		Match: func(choices []string) bool {
			return simulate.Any(choices, "versions=legacy_only", "versions=tls10_only") && simulate.Any(choices, "expiry=today", "expiry=29_days")
		},
		Differences: simulate.Same(simulate.Definition, simLegacyOnlyNote,
			"/endpoints/0/assessment/expiring_soon", "/summary/expiring_soon_count", "/summary/expiring_soon_pct"),
	},
}

func TestSimulatedMatrix(t *testing.T) {
	simHarness(simStanding).Matrix(t, simMatrixBase(t), simMatrixAxes(), simMatrixAlone, simMatrixTogether)
}
