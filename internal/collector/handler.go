package collector

import (
	"time"

	"github.com/locktivity/epack-collector-tls/docs/schema"
	"github.com/locktivity/epack/componentsdk"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        "tls",
		Version:     version,
		Commit:      commit,
		Description: "Collects public TLS certificate and protocol posture",
		Schemas:     schema.Schemas(),
		TraceMap:    schema.TraceMap,
		Timeout:     30 * time.Minute,
	}
}

// Run is the collector's handler. It fails only for invalid configuration,
// and otherwise emits the posture of every endpoint with a gap recorded for
// each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	endpoints, err := getEndpoints(ctx.Config(), "endpoints")
	if err != nil {
		return componentsdk.NewConfigError("endpoints: %v", err)
	}
	if len(endpoints) == 0 {
		return componentsdk.NewConfigError("endpoints is required")
	}

	dialer := componentsdk.NewDialer(ctx)
	posture := Collect(ctx.Context(), Config{
		Endpoints:  endpoints,
		Dial:       dialer.DialContext,
		RootCAs:    dialer.RootCAs(),
		Now:        func() time.Time { return componentsdk.Now(ctx) },
		Recorder:   componentsdk.Records(ctx),
		OnProgress: ctx.Progress,
	})

	return ctx.Emit([]componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(ArtifactPath, posture, componentsdk.ArtifactMeta{
			Schema:      SchemaID,
			DisplayName: "TLS posture",
			Description: "Certificate and protocol posture for configured public endpoints.",
		}),
	})
}
