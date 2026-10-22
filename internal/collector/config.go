package collector

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func getEndpoints(cfg map[string]any, key string) ([]Endpoint, error) {
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

	endpoints := make([]Endpoint, 0, len(items))
	for i, item := range items {
		endpoint, err := parseEndpointValue(item)
		if err != nil {
			return nil, fmt.Errorf("item at index %d: %w", i, err)
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func parseEndpointValue(value any) (Endpoint, error) {
	switch endpoint := value.(type) {
	case string:
		return parseEndpointString(endpoint)
	case map[string]any:
		host, _ := endpoint["host"].(string)
		port := intFromAny(endpoint["port"])
		if port == 0 {
			port = 443
		}
		return NewEndpoint(host, port)
	default:
		return Endpoint{}, fmt.Errorf("expected endpoint object or string, got %T", value)
	}
}

func parseEndpointString(value string) (Endpoint, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimSuffix(value, "/")
	if value == "" {
		return Endpoint{}, fmt.Errorf("host is required")
	}

	host, portString, err := net.SplitHostPort(value)
	if err != nil {
		host = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
		return NewEndpoint(host, 443)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid port %q", portString)
	}
	return NewEndpoint(host, port)
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
