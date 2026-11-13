package collector

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// simRosterPath is the tls sandbox's roster in v1 form, which cmd/derive in
// epack-collector-sandboxes converts from sandboxes/tls/roster.json and the
// refresh workflow commits here.
const simRosterPath = "testdata/simulator/tls.roster.json"

// simClock is the time of every simulated run.
var simClock = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func simBase(t testing.TB) *roster.Roster {
	t.Helper()
	r, err := roster.Load(simRosterPath)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// simConfig scans a roster's endpoints at the audit level, as the sandbox
// does.
func simConfig(r *roster.Roster) map[string]any {
	return map[string]any{
		"level": "audit",
		"endpoints": simulate.Each(r.Hosts.Endpoints, func(e roster.TLSEndpoint) any {
			return net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
		}),
	}
}

// simVersions are the TLS versions crypto/tls serves, by normalized term.
var simVersions = map[string]uint16{
	roster.TLSv10: tls.VersionTLS10, roster.TLSv11: tls.VersionTLS11, roster.TLSv12: tls.VersionTLS12, roster.TLSv13: tls.VersionTLS13,
}

// simNetwork is the servers a roster's tls block describes, by the address
// the collector dials, and the roots a client trusts.
type simNetwork struct {
	servers map[string]simServer
	roots   *x509.CertPool
}

// simServer answers a handshake with the highest version it accepts that
// the client offers, and turns down a client that offers none of them. At
// TLS 1.2 and below it negotiates the roster's cipher suite. crypto/tls
// picks the TLS 1.3 suite itself.
type simServer struct {
	accepts []uint16
	suite   *tls.CipherSuite
	cert    tls.Certificate
}

// newSimNetwork builds the endpoints of r as they stand at now. Each
// certificate chains to the roster's root through CAs with the roster's
// chain names, and the roots the terms trust make up the pool.
func newSimNetwork(r *roster.Roster, now time.Time) *simNetwork {
	n := &simNetwork{servers: map[string]simServer{}, roots: x509.NewCertPool()}
	for name, term := range r.Terms.TLSRoots {
		if term == roster.TLSRootTrusted {
			n.roots.AddCert(simCA(name, nil, now).cert)
		}
	}
	for _, e := range r.Hosts.Endpoints {
		s := simServer{}
		for vendor, term := range r.Terms.TLSVersions {
			if v, ok := simVersions[term]; ok && slices.Contains(e.Accepts, vendor) {
				s.accepts = append(s.accepts, v)
			}
		}
		slices.Sort(s.accepts)
		s.suite = simSuite(e.CipherSuite)
		if e.Certificate != nil {
			var selfTrusted bool
			s.cert, selfTrusted = simLeaf(e, now)
			if selfTrusted && r.Terms.TLSRoots[e.Certificate.Root] == roster.TLSRootTrusted {
				n.roots.AddCert(s.cert.Leaf)
			}
		}
		n.servers[net.JoinHostPort(strings.ToLower(e.Host), strconv.Itoa(e.Port))] = s
	}
	return n
}

// dial connects to the server at address over an in-memory pipe. An
// address with no server, or one whose server accepts no version, refuses
// the connection, as a port nothing listens on does.
func (n *simNetwork) dial(_ context.Context, network, address string) (net.Conn, error) {
	s, ok := n.servers[address]
	if !ok || len(s.accepts) == 0 {
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	client, server := net.Pipe()
	go s.serve(server)
	return client, nil
}

func (s simServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = tls.Server(conn, &tls.Config{GetConfigForClient: s.config}).Handshake()
}

func (s simServer) config(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	version := s.accepts[len(s.accepts)-1]
	for _, v := range slices.Backward(s.accepts) {
		if slices.Contains(hello.SupportedVersions, v) {
			version = v
			break
		}
	}
	// #nosec G402 -- the simulated endpoints serve old versions on purpose.
	cfg := &tls.Config{MinVersion: version, MaxVersion: version}
	if s.cert.Leaf != nil {
		cfg.Certificates = []tls.Certificate{s.cert}
	}
	if s.suite != nil && version <= tls.VersionTLS12 && slices.Contains(s.suite.SupportedVersions, version) {
		cfg.CipherSuites = []uint16{s.suite.ID}
	}
	return cfg, nil
}

// simSuite is the cipher suite crypto/tls names name, or nil.
func simSuite(name string) *tls.CipherSuite {
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// simLeaf issues e's certificate and returns it with the certificates it
// presents after it, and whether the leaf is its own root.
func simLeaf(e roster.TLSEndpoint, now time.Time) (tls.Certificate, bool) {
	c := e.Certificate
	names := c.Chain
	if len(names) == 0 {
		names = []string{cmpOr(c.SubjectCommonName, e.Host)}
	}
	selfSigned := c.Root != "" && c.Root == names[0] && len(names) == 1
	var parent *simIssuer
	var presented [][]byte
	if !selfSigned {
		parentName := c.Root
		if parentName == "" {
			// The leaf chains to no root: its issuer's issuer is missing.
			parentName = "Simulator missing issuer of " + names[len(names)-1]
		}
		parent = simCA(parentName, nil, now)
		for i := len(names) - 1; i >= 1; i-- {
			parent = simCA(names[i], parent, now)
			presented = append([][]byte{parent.cert.Raw}, presented...)
		}
	}
	key := simKey(names[0], c.PublicKeyAlgorithm)
	tmpl := &x509.Certificate{
		SerialNumber: simSerial(c.SerialNumber, e.Host),
		Subject:      pkix.Name{CommonName: cmpOr(c.SubjectCommonName, names[0])},
		DNSNames:     c.DNSNames,
		NotBefore:    simTime(c.NotBefore, now, -1, c.ValidFromDaysAgo, 30),
		NotAfter:     simTime(c.NotAfter, now, 1, &c.ExpiresInDays, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, ip := range c.IPAddresses {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	if c.SignatureAlgorithm != "" {
		tmpl.SignatureAlgorithm = simSignatureAlgorithm(c.SignatureAlgorithm)
	}
	issuerCert, issuerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		issuerCert, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, key.Public(), issuerKey)
	if err != nil {
		panic(fmt.Sprintf("simulator: certificate for %s: %v", e.Host, err))
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: append([][]byte{der}, presented...), PrivateKey: key, Leaf: leaf}, selfSigned
}

// simTime is a certificate's validity bound: the roster's absolute time when
// it gives one, or else days whole days from now, rounded down, placed half
// a day inside the day so either rounding of a fraction shows. sign is -1
// for a time days before now. Without either, the bound is fallback days
// away.
func simTime(absolute string, now time.Time, sign int, days *int, fallback int) time.Time {
	if absolute != "" {
		at, err := time.Parse(time.RFC3339, absolute)
		if err != nil {
			panic(err)
		}
		return at
	}
	d := fallback
	if days != nil {
		d = *days
	}
	return now.Add(time.Duration(sign) * (time.Duration(d)*24*time.Hour + 12*time.Hour))
}

func simSerial(serial, host string) *big.Int {
	if n, ok := new(big.Int).SetString(serial, 10); ok {
		return n
	}
	sum := sha256.Sum256([]byte(host))
	return new(big.Int).SetBytes(sum[:16])
}

func simSignatureAlgorithm(name string) x509.SignatureAlgorithm {
	for a := x509.MD2WithRSA; a <= x509.PureEd25519; a++ {
		if a.String() == name {
			return a
		}
	}
	panic("simulator: no signature algorithm " + name)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// simIssuer is a CA the simulator signs with, and its path from its root.
type simIssuer struct {
	id   string
	cert *x509.Certificate
	key  crypto.Signer
}

var (
	simCAsMu sync.Mutex
	simCAs   = map[string]*simIssuer{}
	simKeys  = map[string]crypto.Signer{}
)

// simCA is the CA named name, signed by parent, or by itself when parent is
// nil. Its validity spans ten years either side of now, and each one is made
// once.
func simCA(name string, parent *simIssuer, now time.Time) *simIssuer {
	simCAsMu.Lock()
	defer simCAsMu.Unlock()
	id := name
	if parent != nil {
		id = parent.id + " > " + name
	}
	if ca, ok := simCAs[id]; ok {
		return ca
	}
	key := simKeyLocked(name, "ECDSA")
	tmpl := &x509.Certificate{
		SerialNumber:          simSerial("", id),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.AddDate(-10, 0, 0),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerCert, issuerKey := tmpl, key
	if parent != nil {
		issuerCert, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, key.Public(), issuerKey)
	if err != nil {
		panic(fmt.Sprintf("simulator: CA %s: %v", name, err))
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	ca := &simIssuer{id: id, cert: cert, key: key}
	simCAs[id] = ca
	return ca
}

func simKey(name, algorithm string) crypto.Signer {
	simCAsMu.Lock()
	defer simCAsMu.Unlock()
	return simKeyLocked(name, algorithm)
}

// simKeyLocked is the key of the named certificate, of the algorithm the
// roster gives, made once.
func simKeyLocked(name, algorithm string) crypto.Signer {
	id := algorithm + " " + name
	if k, ok := simKeys[id]; ok {
		return k
	}
	var k crypto.Signer
	var err error
	switch algorithm {
	case "RSA":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case "", "ECDSA":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		panic("simulator: no key algorithm " + algorithm)
	}
	if err != nil {
		panic(err)
	}
	simKeys[id] = k
	return k
}

// simHarness runs the collector against the servers of the roster Simulate
// last answered for. The collector dials TLS, not HTTP, so Simulate answers
// no requests and Collect gives the run the servers and the roots.
func simHarness(standing simulate.Differences) simulate.Harness {
	var network *simNetwork
	var config map[string]any
	return simulate.Harness{
		Simulate: func(r *roster.Roster, _ int) []collectortest.Response {
			network, config = newSimNetwork(r, simClock), simConfig(r)
			return nil
		},
		Collect: func(t *testing.T, responses []collectortest.Response) componentsdk.InProcessResult {
			return simulate.InProcess(t, Spec("test", "simulator"), Run, componentsdk.InProcessOptions{
				Config:  config,
				Dial:    network.dial,
				RootCAs: network.roots,
				Clock:   func() time.Time { return simClock },
			}, responses)
		},
		Artifacts:  []simulate.Artifact{{Schema: roster.TLS, Path: ArtifactPath}},
		Standing:   standing,
		Coverage:   true,
		Uncompared: simUncompared,
	}
}
