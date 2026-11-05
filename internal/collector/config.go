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
		port, err := configuredPort(endpoint["port"])
		if err != nil {
			return Endpoint{}, err
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

// configuredPort reads the port of an endpoint object. A missing port means
// 443, and NewEndpoint checks the range.
func configuredPort(value any) (int, error) {
	switch v := value.(type) {
	case nil:
		return 443, nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		port, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("invalid port %q", v)
		}
		return port, nil
	default:
		return 0, fmt.Errorf("invalid port %v", v)
	}
}
