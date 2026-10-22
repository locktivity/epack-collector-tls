// epack-collector-tls collects public TLS posture for configured endpoints.
package main

import (
	"github.com/locktivity/epack-collector-tls/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(collector.Spec(Version, Commit), collector.Run)
}
