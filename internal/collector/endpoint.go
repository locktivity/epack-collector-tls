package collector

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

func NewEndpoint(host string, port int) (Endpoint, error) {
	host = normalizeHost(host)
	if host == "" {
		return Endpoint{}, fmt.Errorf("host is required")
	}
	if port < 1 || port > 65535 {
		return Endpoint{}, fmt.Errorf("port must be between 1 and 65535")
	}
	if !validHost(host) {
		return Endpoint{}, fmt.Errorf("host %q is not a valid DNS name or IP address", host)
	}
	return Endpoint{Host: host, Port: port}, nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func validHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	for i, r := range label {
		if r > unicode.MaxASCII {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
			return false
		}
		if (i == 0 || i == len(label)-1) && r == '-' {
			return false
		}
	}
	return true
}
