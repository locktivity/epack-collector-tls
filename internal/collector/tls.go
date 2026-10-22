package collector

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const expiringSoonDays = 30

// Offer every implemented cipher suite, including the insecure ones Go drops
// from its defaults since 1.22, so legacy-only servers are detected instead of
// probing as unsupported.
var probeCipherSuites = allCipherSuiteIDs()

const handshakeOperation = "tls.handshake"

var probes = []struct {
	version   uint16
	operation string
	field     string
}{
	{tls.VersionTLS10, "tls.probe.tls10", "tls_1_0"},
	{tls.VersionTLS11, "tls.probe.tls11", "tls_1_1"},
	{tls.VersionTLS12, "tls.probe.tls12", "tls_1_2"},
	{tls.VersionTLS13, "tls.probe.tls13", "tls_1_3"},
}

// gap is a value left out of an endpoint's result, by its pointer within the
// result, and the error that kept it out.
type gap struct {
	pointer string
	err     error
}

type scanner struct {
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	roots    *x509.CertPool
	timeout  time.Duration
	progress func(current, total int64, message string)
}

// endpointScan is one endpoint's result as the run's steps fill it in, with
// the values left out of it so far.
type endpointScan struct {
	index    int
	endpoint Endpoint
	now      time.Time
	rec      *componentsdk.Recorder
	result   EndpointResult
	gaps     []gap
	// negotiated is the version the modern handshake settled on, which needs
	// no probe of its own.
	negotiated uint16
	// unreachable is set when the endpoint answered the modern handshake with
	// a refused connection or a name that does not exist. It accepts no TLS
	// version, so no probe runs.
	unreachable          bool
	legacyErr, modernErr error
}

func newEndpointScan(index int, endpoint Endpoint, rec *componentsdk.Recorder) endpointScan {
	return endpointScan{
		index:    index,
		endpoint: endpoint,
		rec:      rec,
		result:   EndpointResult{Host: endpoint.Host, Port: endpoint.Port, TLS: &TLSDetails{}},
	}
}

// leaveOut records a gap for each value err kept out of the endpoint's
// result, by its pointer within the result.
func (e *endpointScan) leaveOut(err error, pointers ...string) {
	e.rec.Helper()
	for _, pointer := range pointers {
		e.rec.NotCollected(location(fmt.Sprintf("/endpoints/%d%s", e.index, pointer)), err)
		e.gaps = append(e.gaps, gap{pointer: pointer, err: err})
	}
}

// connect makes the modern handshake, judging the certificate at e.now. An
// endpoint that turns the handshake down, with a TLS alert or a reply that is
// not TLS, has answered, and so has one whose name does not exist or whose
// port refuses the connection. A timeout, a reset, or any other failure
// leaves out the values that depended on the handshake, each with a gap.
func (s scanner) connect(ctx context.Context, e *endpointScan) {
	result := &e.result
	state, err := s.handshake(ctx, e.endpoint, handshakeOperation, tls.VersionTLS12, 0)
	switch {
	case err == nil:
		e.negotiated = state.Version
		result.Reachable = ptr(true)
		result.TLS.NegotiatedVersion = tlsVersionName(state.Version)
		result.TLS.NegotiatedCipherSuite = tls.CipherSuiteName(state.CipherSuite)
		if len(state.PeerCertificates) > 0 {
			result.Certificate = summarizeCertificate(e.endpoint.Host, state.PeerCertificates, s.roots, e.now)
		}
	case unreachable(err):
		e.unreachable = true
		result.Reachable = ptr(false)
		result.Errors = append(result.Errors, "TLS handshake failed: "+err.Error())
		result.TLS.ProtocolSupport = ProtocolSupport{TLS10: ptr(false), TLS11: ptr(false), TLS12: ptr(false), TLS13: ptr(false)}
	case turnedDown(err):
		result.Reachable = ptr(false)
		result.Errors = append(result.Errors, "TLS handshake failed: "+err.Error())
	default:
		result.Errors = append(result.Errors, "TLS handshake failed: "+err.Error())
		e.leaveOut(err, "/reachable", "/tls/negotiated_version", "/tls/negotiated_cipher_suite", "/certificate",
			"/assessment/certificate_valid", "/assessment/hostname_valid", "/assessment/expired", "/assessment/expiring_soon")
	}
}

// probe tries each TLS version the modern handshake did not settle on, one
// handshake per version. A version the endpoint turns down reads as false,
// and a probe that fails another way leaves the version out with a gap.
func (s scanner) probe(ctx context.Context, e *endpointScan) {
	if e.unreachable {
		return
	}
	support := &e.result.TLS.ProtocolSupport
	for _, p := range probes {
		if p.version == e.negotiated {
			support.set(p.version, ptr(true))
			continue
		}
		_, err := s.handshake(ctx, e.endpoint, p.operation, p.version, p.version)
		switch {
		case err == nil:
			support.set(p.version, ptr(true))
		case turnedDown(err):
			support.set(p.version, ptr(false))
		default:
			e.result.Errors = append(e.result.Errors, tlsVersionName(p.version)+" probe failed: "+err.Error())
			e.leaveOut(err, "/tls/protocol_support/"+p.field)
			switch {
			case p.version <= tls.VersionTLS11 && e.legacyErr == nil:
				e.legacyErr = err
			case p.version >= tls.VersionTLS12 && e.modernErr == nil:
				e.modernErr = err
			}
		}
	}
}

// assess judges the endpoint from what the steps read, and leaves out each
// protocol judgment a failed probe left unknown.
func (e *endpointScan) assess() {
	e.result.Assessment = assess(e.result, e.now)
	if e.result.Assessment.ModernProtocol == nil {
		e.leaveOut(e.modernErr, "/assessment/modern_protocol")
	}
	if e.result.Assessment.LegacyProtocolSupported == nil {
		e.leaveOut(e.legacyErr, "/assessment/legacy_protocol_supported")
	}
}

func (s scanner) handshake(ctx context.Context, endpoint Endpoint, operation string, minVersion uint16, maxVersion uint16) (*tls.ConnectionState, error) {
	deadline := time.Now().Add(s.timeout)
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	dialCtx = componentsdk.WithOperation(dialCtx, componentsdk.Operation{Name: operation})

	address := net.JoinHostPort(endpoint.Host, fmt.Sprintf("%d", endpoint.Port))
	rawConn, err := s.dial(dialCtx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rawConn.Close() }()
	// The connection's deadline bounds the handshake, so a timeout fails a read
	// that the dialer counts against the operation. A context that expired
	// would close the connection instead, which reads as the collector's own
	// close and goes uncounted.
	_ = rawConn.SetDeadline(deadline)

	// #nosec G402 -- verification is performed manually so invalid certificates can be reported as evidence.
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         endpoint.Host,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		CipherSuites:       probeCipherSuites,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := tlsConn.ConnectionState()
	return &state, nil
}

// unreachable reports whether a dial failed with an answer: the host's name
// does not exist, or nothing listens on the port.
func unreachable(err error) bool {
	var dnsErr *net.DNSError
	return errors.Is(err, syscall.ECONNREFUSED) || (errors.As(err, &dnsErr) && dnsErr.IsNotFound)
}

// turnedDown reports whether the endpoint answered a handshake by turning it
// down: with a TLS alert, or with a reply that is not TLS at all.
func turnedDown(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" {
		return true
	}
	var header tls.RecordHeaderError
	return errors.As(err, &header)
}

func (p *ProtocolSupport) set(version uint16, supported *bool) {
	switch version {
	case tls.VersionTLS10:
		p.TLS10 = supported
	case tls.VersionTLS11:
		p.TLS11 = supported
	case tls.VersionTLS12:
		p.TLS12 = supported
	case tls.VersionTLS13:
		p.TLS13 = supported
	}
}

func allCipherSuiteIDs() []uint16 {
	var ids []uint16
	for _, suite := range tls.CipherSuites() {
		ids = append(ids, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		ids = append(ids, suite.ID)
	}
	return ids
}

func summarizeCertificate(host string, chain []*x509.Certificate, roots *x509.CertPool, now time.Time) *Certificate {
	leaf := chain[0]
	cert := &Certificate{
		SubjectCommonName:  leaf.Subject.CommonName,
		IssuerCommonName:   leaf.Issuer.CommonName,
		SerialNumber:       leaf.SerialNumber.String(),
		NotBefore:          leaf.NotBefore,
		NotAfter:           leaf.NotAfter,
		ExpiresInDays:      int(leaf.NotAfter.Sub(now).Hours() / 24),
		DNSNames:           append([]string{}, leaf.DNSNames...),
		IPAddresses:        ipStrings(leaf.IPAddresses),
		FingerprintSHA256:  fingerprintSHA256(leaf.Raw),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
		ChainLength:        len(chain),
		HostnameValid:      leaf.VerifyHostname(host) == nil,
	}
	cert.TrustedChain = verifyChain(chain, roots, now) == nil
	return cert
}

// verifyChain checks that the chain leads to a trusted root. The hostname and
// the leaf's validity window are reported on their own, so the chain is judged
// without the hostname and at a moment inside the leaf's window: an expired
// certificate from a trusted CA reads as expired, not as untrusted.
func verifyChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	leaf := chain[0]
	at := now
	if at.After(leaf.NotAfter) {
		at = leaf.NotAfter
	}
	if at.Before(leaf.NotBefore) {
		at = leaf.NotBefore
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
	})
	return err
}

// assess judges an endpoint from what was read. A value whose basis was left
// out is left out too.
func assess(result EndpointResult, now time.Time) Assessment {
	assessment := Assessment{}
	issues := []string{}

	if result.Reachable != nil && !*result.Reachable {
		issues = append(issues, "Endpoint was not reachable over modern TLS")
	}

	switch {
	case result.Reachable == nil:
	case result.Certificate == nil:
		issues = append(issues, "No certificate was presented")
		assessment.CertificateValid = ptr(false)
		assessment.HostnameValid = ptr(false)
		assessment.Expired = ptr(false)
		assessment.ExpiringSoon = ptr(false)
	default:
		certificate := *result.Certificate
		notYetValid := certificate.NotBefore.After(now)
		expired := certificateExpired(certificate, now)
		expiringSoon := !expired && certificate.ExpiresInDays <= expiringSoonDays
		assessment.HostnameValid = ptr(certificate.HostnameValid)
		assessment.Expired = ptr(expired)
		assessment.ExpiringSoon = ptr(expiringSoon)
		assessment.CertificateValid = ptr(certificate.TrustedChain && certificate.HostnameValid &&
			!expired && !notYetValid)

		if !certificate.TrustedChain {
			issues = append(issues, "Certificate chain is not trusted")
		}
		if !certificate.HostnameValid {
			issues = append(issues, "Certificate hostname does not match the endpoint")
		}
		if notYetValid {
			issues = append(issues, "Certificate is not yet valid")
		}
		if expired {
			issues = append(issues, "Certificate is expired")
		} else if expiringSoon {
			issues = append(issues, "Certificate expires within 30 days")
		}
	}

	support := result.TLS.ProtocolSupport
	assessment.ModernProtocol = either(support.TLS12, support.TLS13)
	assessment.LegacyProtocolSupported = either(support.TLS10, support.TLS11)
	if assessment.ModernProtocol != nil && !*assessment.ModernProtocol {
		issues = append(issues, "TLS 1.2 or TLS 1.3 support was not detected")
	}
	if assessment.LegacyProtocolSupported != nil && *assessment.LegacyProtocolSupported {
		issues = append(issues, "TLS 1.0 or TLS 1.1 is supported")
	}

	assessment.Issues = issues
	return assessment
}

// either is true when a or b is true, false when both are false, and unknown
// otherwise.
func either(a, b *bool) *bool {
	switch {
	case (a != nil && *a) || (b != nil && *b):
		return ptr(true)
	case a != nil && b != nil:
		return ptr(false)
	default:
		return nil
	}
}

func certificateExpired(cert Certificate, now time.Time) bool {
	return !cert.NotAfter.After(now)
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func fingerprintSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func ipStrings(ips []net.IP) []string {
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return result
}
