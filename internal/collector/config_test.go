package collector

import (
	"testing"
)

func TestGetEndpointsFromObjects(t *testing.T) {
	endpoints, err := getEndpoints(map[string]any{
		"endpoints": []any{
			map[string]any{"host": "App.Example.com", "port": float64(8443)},
			map[string]any{"host": "api.example.com"},
			map[string]any{"host": "web.example.com", "port": "9443"},
		},
	}, "endpoints")
	if err != nil {
		t.Fatalf("getEndpoints returned error: %v", err)
	}
	if len(endpoints) != 3 {
		t.Fatalf("len(endpoints) = %d, want 3", len(endpoints))
	}
	if endpoints[0].Host != "app.example.com" || endpoints[0].Port != 8443 {
		t.Errorf("first endpoint = %+v, want app.example.com:8443", endpoints[0])
	}
	if endpoints[1].Host != "api.example.com" || endpoints[1].Port != 443 {
		t.Errorf("second endpoint = %+v, want api.example.com:443", endpoints[1])
	}
	if endpoints[2].Host != "web.example.com" || endpoints[2].Port != 9443 {
		t.Errorf("third endpoint = %+v, want web.example.com:9443", endpoints[2])
	}
}

func TestGetEndpointsRejectsInvalidObjectPort(t *testing.T) {
	for name, port := range map[string]any{
		"word":         "https",
		"protocol":     "8443/tcp",
		"inner space":  "84 43",
		"boolean":      true,
		"zero":         float64(0),
		"out of range": float64(70000),
	} {
		t.Run(name, func(t *testing.T) {
			endpoints, err := getEndpoints(map[string]any{
				"endpoints": []any{map[string]any{"host": "app.example.com", "port": port}},
			}, "endpoints")
			if err == nil {
				t.Errorf("port %v gave endpoints %+v, want an error", port, endpoints)
			}
		})
	}
}

func TestGetEndpointsFromStrings(t *testing.T) {
	endpoints, err := getEndpoints(map[string]any{
		"endpoints": []any{
			"https://app.example.com",
			"api.example.com:9443",
		},
	}, "endpoints")
	if err != nil {
		t.Fatalf("getEndpoints returned error: %v", err)
	}
	if endpoints[0].Host != "app.example.com" || endpoints[0].Port != 443 {
		t.Errorf("first endpoint = %+v, want app.example.com:443", endpoints[0])
	}
	if endpoints[1].Host != "api.example.com" || endpoints[1].Port != 9443 {
		t.Errorf("second endpoint = %+v, want api.example.com:9443", endpoints[1])
	}
}

func TestParseEndpointStringHandlesIPv6(t *testing.T) {
	tests := []struct {
		value string
		host  string
		port  int
	}{
		{"2001:db8::1", "2001:db8::1", 443},
		{"[2001:db8::1]", "2001:db8::1", 443},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
	}

	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			endpoint, err := parseEndpointString(test.value)
			if err != nil {
				t.Fatalf("parseEndpointString returned error: %v", err)
			}
			if endpoint.Host != test.host || endpoint.Port != test.port {
				t.Errorf("endpoint = %+v, want %s port %d", endpoint, test.host, test.port)
			}
		})
	}
}

func TestParseEndpointStringRejectsInvalidPort(t *testing.T) {
	if _, err := parseEndpointString("app.example.com:not-a-port"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGetEndpointsRejectsBadShape(t *testing.T) {
	_, err := getEndpoints(map[string]any{"endpoints": "app.example.com"}, "endpoints")
	if err == nil {
		t.Fatal("expected error")
	}
}
