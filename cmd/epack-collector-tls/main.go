// epack-collector-tls collects public TLS posture for configured endpoints.
package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/locktivity/epack-collector-tls/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "tls",
		Version:     Version,
		Commit:      Commit,
		Description: "Collects public TLS certificate and protocol posture",
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	endpoints, err := getEndpoints(ctx.Config(), "endpoints")
	if err != nil {
		return componentsdk.NewConfigError("endpoints: %v", err)
	}
	if len(endpoints) == 0 {
		return componentsdk.NewConfigError("endpoints is required")
	}

	posture, err := collector.Collect(ctx.Context(), collector.Config{
		Endpoints:  endpoints,
		OnStatus:   ctx.Status,
		OnProgress: ctx.Progress,
	})
	if err != nil {
		return componentsdk.NewNetworkError("collecting TLS posture: %v", err)
	}

	return ctx.Emit([]componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact("artifacts/tls.json", posture, componentsdk.ArtifactMeta{
			Schema:      "evidencepack/tls@v1",
			DisplayName: "TLS posture",
			Description: "Certificate and protocol posture for configured public endpoints.",
		}),
	})
}

func getEndpoints(cfg map[string]any, key string) ([]collector.Endpoint, error) {
	if cfg == nil {
		return nil, nil
	}
	raw, ok := cfg[key]
	if !ok {
		return nil, nil
	}

	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("expected array of endpoint objects or strings, got %T", raw)
	}

	endpoints := make([]collector.Endpoint, 0, len(items))
	for i, item := range items {
		endpoint, err := parseEndpointValue(item)
		if err != nil {
			return nil, fmt.Errorf("item at index %d: %w", i, err)
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func parseEndpointValue(value any) (collector.Endpoint, error) {
	switch endpoint := value.(type) {
	case string:
		return parseEndpointString(endpoint)
	case map[string]any:
		host, _ := endpoint["host"].(string)
		port := intFromAny(endpoint["port"])
		if port == 0 {
			port = 443
		}
		return collector.NewEndpoint(host, port)
	default:
		return collector.Endpoint{}, fmt.Errorf("expected endpoint object or string, got %T", value)
	}
}

func parseEndpointString(value string) (collector.Endpoint, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimSuffix(value, "/")
	if value == "" {
		return collector.Endpoint{}, fmt.Errorf("host is required")
	}

	host, portString, err := net.SplitHostPort(value)
	if err != nil {
		host = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
		return collector.NewEndpoint(host, 443)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return collector.Endpoint{}, fmt.Errorf("invalid port %q", portString)
	}
	return collector.NewEndpoint(host, port)
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
}
