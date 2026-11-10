package collector

import (
	"crypto/tls"
	"net"
	"slices"
	"strconv"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestRunDeclaresTheConfiguredEndpointsAsTargets(t *testing.T) {
	modern := tlsServer(t, serverConfig(t, tls.VersionTLS12, tls.VersionTLS13, tls.NoClientCert))
	other := tlsServer(t, serverConfig(t, tls.VersionTLS12, tls.VersionTLS13, tls.NoClientCert))
	closed := closedEndpoint(t)

	tests := []struct {
		name      string
		level     string
		endpoints []Endpoint
		count     int
		complete  bool
	}{
		{name: "every endpoint answers", level: "audit", endpoints: []Endpoint{modern, other}, count: 2, complete: true},
		{name: "a closed port", level: "audit", endpoints: []Endpoint{modern, closed}, count: 2, complete: false},
		{name: "a trust run", level: "trust", endpoints: []Endpoint{modern, other}, complete: true},
		{name: "a trust run with a closed port", level: "trust", endpoints: []Endpoint{modern, closed}, complete: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runWithEndpoints(t, tt.level, tt.endpoints)
			if len(res.Result.Targets) != 1 {
				t.Fatalf("targets = %+v, want the endpoints alone", res.Result.Targets)
			}
			d := res.Result.Targets[0]
			if d.Kind != componentsdk.TargetEndpoint || d.ChosenBy != componentsdk.ChosenByConfig || d.ConfigKey != "endpoints" {
				t.Errorf("kind = %q chosen_by = %q config_key = %q, want endpoint, config_list, endpoints", d.Kind, d.ChosenBy, d.ConfigKey)
			}
			if d.At == nil || d.At.Path != ArtifactPath || d.At.Pointer != "/endpoints" || d.At.Schema != SchemaID {
				t.Errorf("at = %+v, want /endpoints in %s", d.At, ArtifactPath)
			}
			if !slices.Equal(d.Name, []string{"/host", "/port"}) || d.Reached != "/reachable" {
				t.Errorf("name = %v reached = %q, want /host and /port, reached at /reachable", d.Name, d.Reached)
			}
			if tt.level == "trust" && d.Count != nil {
				t.Errorf("count = %d, want none at trust", *d.Count)
			}
			if tt.level == "audit" && (d.Count == nil || *d.Count != tt.count) {
				t.Errorf("count = %v, want %d", d.Count, tt.count)
			}
			if d.Complete == nil || *d.Complete != tt.complete {
				t.Errorf("complete = %v, want %t", d.Complete, tt.complete)
			}
			for _, f := range res.Result.Checks {
				if f.Check == componentsdk.CheckTargets {
					t.Errorf("targets check: %s %s", f.Pointer, f.Message)
				}
			}
		})
	}
}

func runWithEndpoints(t *testing.T, level string, endpoints []Endpoint) componentsdk.InProcessResult {
	t.Helper()
	configured := make([]any, len(endpoints))
	for i, e := range endpoints {
		configured[i] = net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	}
	var dialer net.Dialer
	res := componentsdk.RunInProcess(Spec("test", "test"), Run, componentsdk.InProcessOptions{
		Config: map[string]any{"endpoints": configured, "level": level},
		Dial:   dialer.DialContext,
	})
	if res.Result == nil {
		t.Fatalf("no collector result; exit %d: %s", res.ExitCode, res.Stderr)
	}
	return res
}

// closedEndpoint returns a loopback port nothing listens on.
func closedEndpoint(t *testing.T) Endpoint {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	address := listener.Addr().(*net.TCPAddr)
	_ = listener.Close()
	endpoint, err := NewEndpoint(address.IP.String(), address.Port)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}
	return endpoint
}
