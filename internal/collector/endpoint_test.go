package collector

import "testing"

func TestNewEndpointNormalizesHost(t *testing.T) {
	endpoint, err := NewEndpoint("  App.Example.COM. ", 443)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}
	if endpoint.Host != "app.example.com" {
		t.Errorf("Host = %q, want app.example.com", endpoint.Host)
	}
	if endpoint.Port != 443 {
		t.Errorf("Port = %d, want 443", endpoint.Port)
	}
}

func TestNewEndpointAllowsIPAddresses(t *testing.T) {
	endpoint, err := NewEndpoint("127.0.0.1", 443)
	if err != nil {
		t.Fatalf("NewEndpoint returned error: %v", err)
	}
	if endpoint.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want 127.0.0.1", endpoint.Host)
	}
}

func TestNewEndpointRejectsInvalidHost(t *testing.T) {
	tests := []string{
		"",
		"localhost",
		"bad host.example.com",
		"-bad.example.com",
		"bad-.example.com",
		"bad_label.example.com",
	}

	for _, host := range tests {
		t.Run(host, func(t *testing.T) {
			if _, err := NewEndpoint(host, 443); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNewEndpointRejectsInvalidPort(t *testing.T) {
	if _, err := NewEndpoint("app.example.com", 0); err == nil {
		t.Fatal("expected error")
	}
	if _, err := NewEndpoint("app.example.com", 65536); err == nil {
		t.Fatal("expected error")
	}
}
