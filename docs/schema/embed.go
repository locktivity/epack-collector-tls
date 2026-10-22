// Package schema embeds the JSON Schema of the collector's artifact and its
// trace map.
package schema

import _ "embed"

//go:embed v1.0.0.json
var posture []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifact to the handshakes and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Schemas maps the artifact path to its JSON Schema, for
// componentsdk.CollectorSpec.Schemas. It is the SDK's evidencepack/tls@v1
// schema with the annotations the output checks read.
func Schemas() map[string][]byte {
	return map[string][]byte{"artifacts/tls.json": posture}
}
