//go:build record

package collector

import (
	"os"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// TestRecord records a sandbox, a host whose endpoints are kept with known
// settings, to testdata/recordings/tls.json for the collectortest suite.
// Record probes each endpoint the run dialed and writes one that accepts the
// same TLS versions and presents a certificate with the same names,
// validity, and trust. It reads the sandbox's domain from SANDBOX_DOMAIN and
// skips when it is not set. The domain becomes example.com, the value of any
// other SANDBOX_ variable becomes a stable fake, and Record writes nothing
// if one remains:
//
//	SANDBOX_DOMAIN=sandbox.example go test -tags record -run 'TestRecord/^tls$' -count=1 ./internal/collector/
func TestRecord(t *testing.T) {
	t.Run("tls", func(t *testing.T) {
		domain := os.Getenv("SANDBOX_DOMAIN")
		if domain == "" {
			t.Skip("set SANDBOX_DOMAIN to record")
		}
		report, err := collectortest.Record(collectortest.RecordOptions{
			Spec: Spec("record", "collectortest"),
			Run:  Run,
			Config: map[string]any{
				"level": "audit",
				"endpoints": []any{
					"modern.tls." + domain,
					"legacy.tls." + domain + ":8443",
					"legacy-only.tls." + domain + ":8444",
					"self-signed.tls." + domain,
					"mismatch.tls." + domain,
					"expired.tls." + domain,
				},
			},
			Out:   "testdata/recordings/tls.json",
			Scrub: collectortest.ScrubRules{Identifiers: collectortest.EnvIdentifiers("SANDBOX_", map[string]string{"SANDBOX_DOMAIN": "example.com"})},
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.ExitCode != 0 {
			t.Errorf("the recorded run exited %d: %+v", report.ExitCode, report.Failure)
		}
		t.Logf("recorded %d endpoints", report.Endpoints)
	})
}
