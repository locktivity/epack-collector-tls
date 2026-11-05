package collector

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	// negotiated is the version the endpoint selected in the modern handshake,
	// whether or not the handshake then completed. It needs no probe of its
	// own.
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
// endpoint that turns the handshake down has answered, and so has one whose
// name does not exist or whose port refuses the connection. A timeout, a
// reset, or any other failure leaves out the values that depended on the
// handshake, each with a gap. The version the endpoint selected is kept even
// when the handshake fails afterward.
func (s scanner) connect(ctx context.Context, e *endpointScan) {
	result := &e.result
	state, selected, err := s.handshake(ctx, e.endpoint, handshakeOperation, tls.VersionTLS12, 0)
	e.negotiated = selected
	switch {
	case err == nil:
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
	case turnedDown(err, selected):
		result.Reachable = ptr(false)
		result.Errors = append(result.Errors, "TLS handshake failed: "+err.Error())
	default:
		result.Errors = append(result.Errors, "TLS handshake failed: "+err.Error())
		e.leaveOut(err, "/reachable", "/tls/negotiated_version", "/tls/negotiated_cipher_suite", "/certificate",
			"/assessment/certificate_valid", "/assessment/hostname_valid", "/assessment/expired", "/assessment/expiring_soon")
	}
}

// probe tries each TLS version the modern handshake did not settle on, one
// handshake per version. A version the endpoint selects reads as true, even
// when the handshake fails afterward. A version the endpoint turns down reads
// as false, and a probe that fails another way leaves the version out with a
// gap.
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
		_, selected, err := s.handshake(ctx, e.endpoint, p.operation, p.version, p.version)
		switch {
		case err == nil || selected == p.version:
			support.set(p.version, ptr(true))
		case turnedDown(err, selected):
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

// handshake makes one handshake that offers minVersion through maxVersion. It
// returns the handshake's state when the handshake completes. It also returns
// the version the endpoint selected, or 0 when the endpoint selected none. An
// endpoint can select a version and fail the handshake later, for example when
// it requires a client certificate (RFC 5246 section 7.4.6).
func (s scanner) handshake(ctx context.Context, endpoint Endpoint, operation string, minVersion uint16, maxVersion uint16) (*tls.ConnectionState, uint16, error) {
	deadline := time.Now().Add(s.timeout)
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	dialCtx = componentsdk.WithOperation(dialCtx, componentsdk.Operation{Name: operation})

	address := net.JoinHostPort(endpoint.Host, fmt.Sprintf("%d", endpoint.Port))
	rawConn, err := s.dial(dialCtx, "tcp", address)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rawConn.Close() }()
	// The connection's deadline bounds the handshake, so a timeout fails a read
	// that the dialer counts against the operation. A context that expired
	// would close the connection instead, which reads as the collector's own
	// close and goes uncounted.
	_ = rawConn.SetDeadline(deadline)

	// A failed handshake has no connection state in crypto/tls. VerifyConnection
	// is called with the state once the endpoint's certificate arrives, and by
	// then the ServerHello has set the version. An endpoint that requires a
	// client certificate fails the handshake only after that, so the version is
	// kept. A handshake that fails between the ServerHello and the certificate
	// reads as one where the endpoint selected no version.
	var selected uint16
	// #nosec G402 -- verification is performed manually so invalid certificates can be reported as evidence.
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         endpoint.Host,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		CipherSuites:       probeCipherSuites,
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			selected = state.Version
			return nil
		},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, selected, err
	}
	state := tlsConn.ConnectionState()
	return &state, state.Version, nil
}

// unreachable reports whether a dial failed with an answer: the host's name
// does not exist, or nothing listens on the port.
func unreachable(err error) bool {
	var dnsErr *net.DNSError
	return errors.Is(err, syscall.ECONNREFUSED) || (errors.As(err, &dnsErr) && dnsErr.IsNotFound)
}

// Alerts that turn down the versions a ClientHello offers, when they answer it
// before any ServerHello (RFC 5246 section 7.4.1.3, RFC 8446 section 6.2).
const (
	alertHandshakeFailure tls.AlertError = 40
	alertProtocolVersion  tls.AlertError = 70
)

// turnedDown reports whether the endpoint answered a handshake by turning it
// down. Any alert after the endpoint selected a version does so. Before that,
// only a handshake_failure or protocol_version alert turns down the offered
// versions. Another alert, such as internal_error, is unrelated to the
// versions. A ServerHello for another version or a reply that is not TLS turns
// them down too.
func turnedDown(err error, selected uint16) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" && opErr.Err != nil {
		// A received alert has an unexported type in crypto/tls. Its text matches
		// the AlertError with the same number, so the texts are compared.
		alert := opErr.Err.Error()
		return selected != 0 || alert == alertHandshakeFailure.Error() || alert == alertProtocolVersion.Error()
	}
	// A server without the offered version answers with an older one in its
	// ServerHello (RFC 8446 appendix D.1). crypto/tls has no error type for
	// that answer, so the message text is matched.
	if strings.Contains(err.Error(), "tls: server selected unsupported protocol version") {
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
		ExpiresInDays:      daysUntil(now, leaf.NotAfter),
		DNSNames:           append([]string{}, leaf.DNSNames...),
		IPAddresses:        ipStrings(leaf.IPAddresses),
		FingerprintSHA256:  fingerprintSHA256(leaf.Raw),
		SignatureAlgorithm: signatureAlgorithm(leaf),
		PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
		ChainLength:        len(chain),
		HostnameValid:      leaf.VerifyHostname(host) == nil,
	}
	cert.TrustedChain = verifyChain(chain, roots, now) == nil
	return cert
}

// daysUntil is the number of whole days from now to t, rounded toward zero.
// It counts in seconds because a time.Duration holds at most about 292 years.
// A certificate with no fixed expiry has a not_after in the year 9999
// (RFC 5280 section 4.1.2.5).
func daysUntil(now, t time.Time) int {
	seconds := t.Unix() - now.Unix()
	// When the seconds and the fraction of a second differ in sign, one second
	// moves across so they match. The division then rounds the whole
	// difference toward zero.
	nanos := t.Nanosecond() - now.Nanosecond()
	switch {
	case seconds > 0 && nanos < 0:
		seconds--
	case seconds < 0 && nanos > 0:
		seconds++
	}
	return int(seconds / (24 * 60 * 60))
}

// signatureAlgorithm names the algorithm the issuer signed cert with. An
// algorithm without a name in crypto/x509 is given as the object identifier
// from the certificate's signatureAlgorithm field (RFC 5280 section 4.1.1.2).
func signatureAlgorithm(cert *x509.Certificate) string {
	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return cert.SignatureAlgorithm.String()
	}
	// Only the fields up to signatureAlgorithm are read. A certificate from a
	// handshake was already parsed by crypto/x509, so this read does not fail.
	var outer struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		return cert.SignatureAlgorithm.String()
	}
	return outer.SignatureAlgorithm.Algorithm.String()
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

// certificateExpired reports whether now is past the certificate's validity
// period, which runs from notBefore through notAfter, inclusive (RFC 5280
// section 4.1.2.5).
func certificateExpired(cert Certificate, now time.Time) bool {
	return now.After(cert.NotAfter)
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
