package core

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// realityPair builds a responder bound to an ephemeral loopback port and an
// initiator, cross-wired by an in-memory signaler. The responder advertises
// whatever address it actually bound, so the initiator learns where to dial
// from the answer — every test below is a real TCP+TLS round trip on loopback.
func realityPair(t *testing.T) (resp, initr *realityTransport, dialerSig, accepterSig *memSignaler) {
	t.Helper()
	// Probe origin "off" keeps the authenticated-path tests hermetic: the background
	// cert-warmer (ADR-0032) never dials out, and these tests only exercise the
	// authenticated path, which does not touch the origin.
	resp, err := newRealityTransport(Config{RealityListen: "127.0.0.1:0", RealitySNI: "www.example.com", RealityProbeOrigin: realityProbeOff}, nil)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	initr, err = newRealityTransport(Config{}, nil)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	dialerSig, accepterSig = newMemSignalerPair()
	return resp, initr, dialerSig, accepterSig
}

// serveEcho accepts on the responder and echoes every stream; it is the exit
// stand-in for the round-trip tests.
func serveEcho(t *testing.T, resp *realityTransport, sig *memSignaler) {
	t.Helper()
	go func() {
		sess, err := resp.Accept(context.Background(), sig)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		echoSession(sess)
	}()
}

func TestRealityTransportRoundTrip(t *testing.T) {
	resp, initr, dialerSig, accepterSig := realityPair(t)
	defer resp.close()
	serveEcho(t, resp, accepterSig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := initr.Dial(ctx, dialerSig)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer sess.Close()

	const label = "example.com:443"
	st, err := sess.OpenStream(ctx, label)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if st.Label() != label {
		t.Fatalf("label = %q, want %q", st.Label(), label)
	}

	msg := []byte("hello reality transport")
	go func() { _, _ = st.Write(msg) }()
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
	_ = st.Close()
}

// TestRealityConcurrentStreams proves streams are independent: several run over
// one session (one TLS connection each) and each echoes its own label back.
func TestRealityConcurrentStreams(t *testing.T) {
	resp, initr, dialerSig, accepterSig := realityPair(t)
	defer resp.close()
	serveEcho(t, resp, accepterSig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := initr.Dial(ctx, dialerSig)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer sess.Close()

	for _, lb := range []string{"a.example:1", "b.example:2", "c.example:3"} {
		st, err := sess.OpenStream(ctx, lb)
		if err != nil {
			t.Fatalf("OpenStream %q: %v", lb, err)
		}
		want := []byte("ping-" + lb)
		go func() { _, _ = st.Write(want) }()
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(st, buf); err != nil {
			t.Fatalf("echo %q: %v", lb, err)
		}
		if string(buf) != string(want) {
			t.Fatalf("echo %q = %q", lb, buf)
		}
		if st.Label() != lb {
			t.Fatalf("label = %q, want %q", st.Label(), lb)
		}
		_ = st.Close()
	}
}

// TestRealityOuterLooksLikeHTTPS confirms the camouflage layer: the stream's
// underlying connection is TLS >= 1.2 with an HTTP ALPN, so on the wire the
// session is a normal HTTPS connection to :443.
func TestRealityOuterLooksLikeHTTPS(t *testing.T) {
	resp, initr, dialerSig, accepterSig := realityPair(t)
	defer resp.close()
	serveEcho(t, resp, accepterSig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := initr.Dial(ctx, dialerSig)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer sess.Close()

	st, err := sess.OpenStream(ctx, "example.com:443")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	rs, ok := st.(*realityStream)
	if !ok {
		t.Fatalf("stream type %T, want *realityStream", st)
	}
	// The client now speaks uTLS (ADR-0032), so the outer connection is a
	// *utls.UConn — still an ordinary TLS >= 1.2 session with an HTTP ALPN.
	tc, ok := rs.Conn.(*utls.UConn)
	if !ok {
		t.Fatalf("underlying conn %T, want *utls.UConn", rs.Conn)
	}
	cs := tc.ConnectionState()
	if cs.Version < tls.VersionTLS12 {
		t.Fatalf("TLS version %#x, want >= 1.2", cs.Version)
	}
	if cs.NegotiatedProtocol != "h2" && cs.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("ALPN = %q, want h2 or http/1.1", cs.NegotiatedProtocol)
	}
}

// TestRealityUnauthenticatedRejectedWhenProbeOff exercises the opt-out: with the
// impersonated origin set to "off", an unauthenticated peer (here a stock crypto/tls
// client, which cannot forge the ClientHello authenticator) is dropped before TLS is
// terminated, so its handshake fails. This is the reject branch of onUnauthenticated.
func TestRealityUnauthenticatedRejectedWhenProbeOff(t *testing.T) {
	resp, err := newRealityTransport(Config{RealityListen: "127.0.0.1:0", RealitySNI: "www.example.com", RealityProbeOrigin: realityProbeOff}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.close()
	if err := resp.ensureListener(); err != nil {
		t.Fatal(err)
	}

	raw, err := net.Dial("tcp", resp.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	tc := tls.Client(raw, &tls.Config{
		ServerName:         "www.example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})
	if err := tc.Handshake(); err == nil {
		t.Fatal("unauthenticated peer completed a handshake; want the connection dropped when the origin is off")
	}
}

const originBanner = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"

// issueOriginCert mints a throwaway CA and a leaf it signs for dnsName, returning a
// root pool holding the CA and a server certificate presenting the leaf. A prober
// that trusts the pool can validate a genuine handshake against this origin.
// leafKey lets a caller choose the leaf's own key class (RSA vs a specific EC
// curve, issue #98); a nil leafKey defaults to ECDSA P-256, the prior fixed
// behaviour, and is the right choice whenever the leaf's key type isn't the point
// of the test.
func issueOriginCert(t *testing.T, dnsName string, notBefore, notAfter time.Time, leafKey crypto.Signer) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Origin CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	if leafKey == nil {
		leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return pool, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey, Leaf: leaf}
}

// startBannerOrigin stands up a TLS origin that reads a request and replies with a
// recognizable banner, standing in for the real site the exit impersonates.
func startBannerOrigin(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	oln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = oln.Close() })
	go func() {
		for {
			c, err := oln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = c.Read(make([]byte, 512)) // consume the replayed opening bytes
				_, _ = c.Write([]byte(originBanner))
			}(c)
		}
	}()
	return oln.Addr().String()
}

// TestRealityProberValidatesOriginChain is the #70 acceptance test. An
// unauthenticated prober — one that cannot forge the ClientHello authenticator —
// validates the presented TLS chain with verification ON and the origin's CA as its
// only root. The handshake succeeds only because the exit splices it to the real
// origin, whose leaf chains to that CA; if the exit had presented a self-signed leaf
// of its own, verification would fail. That is exactly the self-signed anomaly #70
// removes.
func TestRealityProberValidatesOriginChain(t *testing.T) {
	const sni = "origin.example"
	pool, originCert := issueOriginCert(t, sni, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil)
	originAddr := startBannerOrigin(t, &tls.Config{Certificates: []tls.Certificate{originCert}})

	resp, err := newRealityTransport(Config{RealityListen: "127.0.0.1:0", RealitySNI: sni, RealityProbeOrigin: originAddr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.close()
	if err := resp.ensureListener(); err != nil {
		t.Fatal(err)
	}

	raw, err := net.Dial("tcp", resp.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))

	// Verification ON, no InsecureSkipVerify: a real chain-validating prober.
	tc := tls.Client(raw, &tls.Config{ServerName: sni, RootCAs: pool})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("prober could not validate the presented chain (self-signed anomaly not removed): %v", err)
	}
	if len(tc.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("handshake succeeded but no chain was verified")
	}
	// Bytes flow through the splice: the prober reads the origin's banner.
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write through splice: %v", err)
	}
	got := make([]byte, 64)
	n, _ := tc.Read(got)
	if !bytes.Contains(got[:n], []byte("HELLO")) {
		t.Fatalf("prober did not receive the origin banner through the splice; got %q", got[:n])
	}
}

// TestRealityAuthenticatedBadTokenBridgesToOrigin proves the ADR-0027 response is
// preserved as the post-termination fallback (ADR-0032). An authenticated client
// (so the exit terminates TLS locally) that then presents a token no session minted
// is reverse-proxied to the origin via the plaintext bridge, receiving its banner.
func TestRealityAuthenticatedBadTokenBridgesToOrigin(t *testing.T) {
	const sni = "origin.example"
	originTLS, err := realityServerTLS(sni) // a self-signed stub is fine; the bridge does not verify it
	if err != nil {
		t.Fatal(err)
	}
	originAddr := startBannerOrigin(t, originTLS)

	resp, err := newRealityTransport(Config{RealityListen: "127.0.0.1:0", RealitySNI: sni, RealityProbeOrigin: originAddr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.close()
	if err := resp.ensureListener(); err != nil {
		t.Fatal(err)
	}

	raw, err := net.Dial("tcp", resp.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tc, err := realityClientHandshake(ctx, raw, sni, resp.realityKey.pub)
	if err != nil {
		t.Fatalf("authenticated handshake: %v", err)
	}
	if err := writeInnerHandshake(tc, make([]byte, realityTokenLen), "probe:1"); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(tc)
	if !bytes.Contains(got, []byte("HELLO")) {
		t.Fatalf("authenticated bad-token connection was not bridged to the origin; got %q", got)
	}
}

// TestRealityMimicTLSStealsOriginBytes is the #92 acceptance test for the static
// certificate data: the terminate-path config now carries the impersonated origin's
// actual certificate chain, byte-for-byte, rather than a leaf that merely copies its
// fields (the prior behaviour, ADR-0032 as first shipped). A fully-validating chain
// check — the "passive DPI" residual ADR-0032 named — succeeds against it, because
// it IS the origin's chain; it is signed by a fresh key of ours, since the exit does
// not and cannot hold the origin's private key.
func TestRealityMimicTLSStealsOriginBytes(t *testing.T) {
	const sni = "steal.example"
	pool, originCert := issueOriginCert(t, sni, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil)
	originAddr := startBannerOrigin(t, &tls.Config{Certificates: []tls.Certificate{originCert}})

	cfg, err := realityMimicTLS(originAddr, sni)
	if err != nil {
		t.Fatalf("mimic: %v", err)
	}
	got := cfg.Certificates[0]

	if !bytes.Equal(got.Certificate[0], originCert.Certificate[0]) {
		t.Fatal("stolen leaf bytes differ from the origin's; want byte-for-byte")
	}

	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Roots: pool}); err != nil {
		t.Fatalf("stolen chain does not validate against the origin's root: %v", err)
	}

	signer, ok := got.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("signing key type = %T, want *ecdsa.PrivateKey", got.PrivateKey)
	}
	if signer.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("signing key matches the stolen leaf's public key; want a fresh, non-matching key (the exit never holds the origin's private key)")
	}
}

// TestRealityTerminatePathPresentsStolenChain is the #92 end-to-end acceptance test:
// an authenticated client completes the terminate-path handshake even though the
// exit presents a certificate chain it does not hold the private key for
// (InsecureSkipCertVerifySignature, third_party/utls), and the chain the client
// actually receives is the origin's real, publicly-chaining bytes rather than a
// self-signed leaf. TestRealityAuthenticatedBadTokenBridgesToOrigin already covers
// that the ADR-0027 bridge (issue #62) still works unmodified on this same
// authenticated path, and TestRealityProberValidatesOriginChain that the raw-splice
// path for an unauthenticated peer (ADR-0032) is untouched.
func TestRealityTerminatePathPresentsStolenChain(t *testing.T) {
	const sni = "origin.example"
	pool, originCert := issueOriginCert(t, sni, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil)
	originAddr := startBannerOrigin(t, &tls.Config{Certificates: []tls.Certificate{originCert}})

	resp, err := newRealityTransport(Config{RealityListen: "127.0.0.1:0", RealitySNI: sni, RealityProbeOrigin: originAddr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.close()
	if err := resp.ensureListener(); err != nil {
		t.Fatal(err)
	}
	resp.warmMimicCert() // force the warm to complete synchronously before dialing

	raw, err := net.Dial("tcp", resp.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tc, err := realityClientHandshake(ctx, raw, sni, resp.realityKey.pub)
	if err != nil {
		t.Fatalf("authenticated handshake against a borrowed, signature-mismatched cert: %v", err)
	}
	defer tc.Close()

	peerCerts := tc.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		t.Fatal("no certificate presented on the terminate path")
	}
	if !bytes.Equal(peerCerts[0].Raw, originCert.Certificate[0]) {
		t.Fatal("terminate-path leaf differs from the origin's; want byte-for-byte")
	}
	if _, err := peerCerts[0].Verify(x509.VerifyOptions{DNSName: sni, Roots: pool}); err != nil {
		t.Fatalf("terminate-path chain does not validate against the origin's root: %v", err)
	}
}

// TestRealityMimicTLSMatchesSignerKeyType is one #98 acceptance test: the fresh key
// that signs a borrowed leaf's CertificateVerify is minted in the origin leaf's own
// key class — here RSA, at the origin's exact bit length — rather than always a
// fixed P-256 ECDSA key regardless of what the origin actually presents (the prior
// behaviour TestRealityMimicTLSStealsOriginBytes still separately covers, since that
// test's origin happens to itself be ECDSA P-256).
func TestRealityMimicTLSMatchesSignerKeyType(t *testing.T) {
	const sni = "steal-rsa.example"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, originCert := issueOriginCert(t, sni, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), rsaKey)
	originAddr := startBannerOrigin(t, &tls.Config{Certificates: []tls.Certificate{originCert}})

	cfg, err := realityMimicTLS(originAddr, sni)
	if err != nil {
		t.Fatalf("mimic: %v", err)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	wantPub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("test setup: stolen leaf public key type = %T, want *rsa.PublicKey", leaf.PublicKey)
	}
	signer, ok := cfg.Certificates[0].PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("signer type = %T, want *rsa.PrivateKey (origin leaf is RSA)", cfg.Certificates[0].PrivateKey)
	}
	if signer.N.BitLen() != wantPub.N.BitLen() {
		t.Fatalf("signer RSA modulus = %d bits, want %d (the origin leaf's size)", signer.N.BitLen(), wantPub.N.BitLen())
	}
	if signer.PublicKey.Equal(wantPub) {
		t.Fatal("signing key matches the stolen leaf's public key; want a fresh, non-matching key of the same class")
	}
}

// TestRealityMimicTLSMatchesSignerCurve is the other #98 acceptance test: class
// parity tracks the specific EC curve, not just "RSA vs EC" — an origin on P-384
// gets a P-384 signer, not the P-256 every origin got before #98 regardless of its
// own curve.
func TestRealityMimicTLSMatchesSignerCurve(t *testing.T) {
	const sni = "steal-p384.example"
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, originCert := issueOriginCert(t, sni, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), ecKey)
	originAddr := startBannerOrigin(t, &tls.Config{Certificates: []tls.Certificate{originCert}})

	cfg, err := realityMimicTLS(originAddr, sni)
	if err != nil {
		t.Fatalf("mimic: %v", err)
	}
	signer, ok := cfg.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("signer type = %T, want *ecdsa.PrivateKey", cfg.Certificates[0].PrivateKey)
	}
	if signer.Curve != elliptic.P384() {
		t.Fatalf("signer curve = %s, want %s (the origin leaf's curve)", signer.Curve.Params().Name, elliptic.P384().Params().Name)
	}
}

// TestRealityMatchingSignerSchemeIsChromeSupported is the #104 regression test — it
// closes the structural gap the issue named: TestRealityMimicTLSMatchesSignerCurve
// only checks that a minted signer's curve matches the origin leaf's, never that the
// mimicked ClientHello (utls.HelloChrome_Auto) actually offers a TLS signature scheme
// for that curve. A P-521 origin leaf satisfied that older test — the signer curve did
// match — while still being unusable at the handshake, since Chrome's ClientHello only
// ever offers ecdsa_secp256r1_sha256 and ecdsa_secp384r1_sha384. This test reads
// utls.HelloChrome_Auto's actual supported_signature_algorithms extension, rather than
// hardcoding an assumption about which schemes it carries, so it keeps working if that
// uTLS profile ever changes.
func TestRealityMatchingSignerSchemeIsChromeSupported(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("uTLS Chrome spec: %v", err)
	}
	var offered map[utls.SignatureScheme]bool
	for _, ext := range spec.Extensions {
		sa, ok := ext.(*utls.SignatureAlgorithmsExtension)
		if !ok {
			continue
		}
		offered = make(map[utls.SignatureScheme]bool, len(sa.SupportedSignatureAlgorithms))
		for _, s := range sa.SupportedSignatureAlgorithms {
			offered[s] = true
		}
	}
	if offered == nil {
		t.Fatal("test setup: utls.HelloChrome_Auto carries no SignatureAlgorithmsExtension")
	}

	// TLS 1.3 binds each ECDSA scheme to one specific curve (RFC 8446 §4.2.3); that
	// mapping is a wire-protocol fact, not a Go implementation detail, so it is safe
	// to state directly here rather than re-deriving it from Go's unexported
	// signatureSchemesForCertificate.
	curveScheme := map[elliptic.Curve]utls.SignatureScheme{
		elliptic.P256(): utls.ECDSAWithP256AndSHA256,
		elliptic.P384(): utls.ECDSAWithP384AndSHA384,
		elliptic.P521(): utls.ECDSAWithP521AndSHA512,
	}

	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		leafKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("%s: generate origin leaf key: %v", curve.Params().Name, err)
		}
		signer, mintErr := realityMatchingSigner(&leafKey.PublicKey)
		wantOffered := offered[curveScheme[curve]]

		if !wantOffered {
			if mintErr == nil {
				t.Fatalf("%s: realityMatchingSigner minted a signer, but scheme %s (%#04x) is not in utls.HelloChrome_Auto's supported_signature_algorithms — the terminate handshake would have no mutually-supported scheme to use it with (issue #104)", curve.Params().Name, curveScheme[curve], uint16(curveScheme[curve]))
			}
			continue // correctly refused; warmMimicCert falls back to the self-signed config
		}
		if mintErr != nil {
			t.Fatalf("%s: realityMatchingSigner refused a curve Chrome's ClientHello does offer (%s, %#04x): %v", curve.Params().Name, curveScheme[curve], uint16(curveScheme[curve]), mintErr)
		}
		es, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("%s: signer type = %T, want *ecdsa.PrivateKey", curve.Params().Name, signer)
		}
		if es.Curve != curve {
			t.Fatalf("%s: signer curve = %s, want %s", curve.Params().Name, es.Curve.Params().Name, curve.Params().Name)
		}
	}

	// The same rule governs the non-ECDSA key classes realityMatchingSigner handles:
	// mint only when the mimicked ClientHello offers a scheme that class can produce.
	// #104 fixed the ECDSA-P521 case; these guard the sibling classes the original
	// fix left untested — Ed25519 was in fact still broken, minting unconditionally.
	//
	// RSA: Chrome offers rsa_pss_rsae_sha256 et al., so an RSA leaf mints.
	if !offered[utls.PSSWithSHA256] {
		t.Fatal("test setup: utls.HelloChrome_Auto unexpectedly offers no RSA-PSS scheme")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA origin leaf key: %v", err)
	}
	if _, err := realityMatchingSigner(&rsaKey.PublicKey); err != nil {
		t.Fatalf("realityMatchingSigner refused an RSA leaf Chrome's ClientHello does support: %v", err)
	}

	// Ed25519: Chrome's ClientHello offers no ed25519 scheme (0x0807 absent), so an
	// Ed25519 leaf must be refused — minting one repeats the P-521 failure mode
	// (mint succeeds, terminate handshake then has no mutually-supported scheme).
	if offered[utls.Ed25519] {
		t.Fatal("test setup: utls.HelloChrome_Auto unexpectedly offers an Ed25519 scheme; the refusal check below assumes it does not")
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 origin leaf key: %v", err)
	}
	if _, err := realityMatchingSigner(edPub); err == nil {
		t.Fatal("realityMatchingSigner minted an Ed25519 signer, but Chrome's ClientHello offers no ed25519 scheme — the terminate handshake would have no mutually-supported scheme (issue #104)")
	}
}

// TestRealityMatchingSignerRejectsUnsupportedKeyType proves the "no new distinguisher"
// half of #98: an origin leaf key class realityMatchingSigner cannot mint a match for
// is refused outright rather than silently substituted with a mismatched class (which
// would just be a different flavor of the tell #98 closes). realityMimicTLS's caller,
// warmMimicCert, already falls back to the self-signed terminate-path config on any
// error here, so refusing is a narrowing of the existing behaviour, not a new failure
// mode.
func TestRealityMatchingSignerRejectsUnsupportedKeyType(t *testing.T) {
	if _, err := realityMatchingSigner("not-a-key"); err == nil {
		t.Fatal("want an error for an unsupported public key type")
	}
}

// rawEventRecorder captures a reality transport or session's raw onEvent(kind, msg
// string) callbacks — mutex-guarded since transports and sessions emit from their
// own spawned goroutines, concurrently with whatever the test's own goroutine does.
// This is a lower-level, unwrapped sibling of pool_test.go's eventRecorder, which
// only ever sees the engine's already-wrapped Event struct: the reality transport
// talks directly in the raw onEvent shape newRealityTransport/newRealitySession take.
type rawEventRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *rawEventRecorder) record(_, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, msg)
}

// drainDuration returns the time.Duration parsed out of the most recent recorded
// message with the given prefix (e.g. "reality: transport stop drained background
// goroutines in "), and whether one was found at all.
func (r *rawEventRecorder) drainDuration(prefix string) (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.msgs) - 1; i >= 0; i-- {
		if !strings.HasPrefix(r.msgs[i], prefix) {
			continue
		}
		d, err := time.ParseDuration(strings.TrimPrefix(r.msgs[i], prefix))
		if err != nil {
			continue
		}
		return d, true
	}
	return 0, false
}

func TestRealitySessionClose(t *testing.T) {
	resp, initr, dialerSig, accepterSig := realityPair(t)
	defer resp.close()
	go func() {
		if _, err := resp.Accept(context.Background(), accepterSig); err != nil {
			t.Errorf("Accept: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := initr.Dial(ctx, dialerSig)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	sess.Close()

	select {
	case <-sess.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed() not signalled after Close()")
	}
	if _, err := sess.OpenStream(context.Background(), "x:1"); err == nil {
		t.Fatal("OpenStream on a closed session should fail")
	}
}

// blockingReadConn wraps a net.Conn so Read only observes the close after a delay,
// simulating a watchControl goroutine that takes a moment to notice and return.
// Long enough to prove a caller genuinely waited for it, not just triggered it.
type blockingReadConn struct {
	net.Conn
	delay     time.Duration
	closeOnce sync.Once
	unblock   chan struct{}
}

func newBlockingReadConn(c net.Conn, delay time.Duration) *blockingReadConn {
	return &blockingReadConn{Conn: c, delay: delay, unblock: make(chan struct{})}
}

func (c *blockingReadConn) Read(p []byte) (int, error) {
	<-c.unblock
	time.Sleep(c.delay)
	return 0, io.EOF
}

func (c *blockingReadConn) Close() error {
	c.closeOnce.Do(func() { close(c.unblock) })
	return c.Conn.Close()
}

// TestRealitySessionCloseJoinsWatchControl is the #65 acceptance test at the
// session level: Close must not return until watchControl has actually exited, not
// merely been signalled. Before the fix, useControl's bare `go` meant Close
// returned as soon as the tracked conns were closed, regardless of whether
// watchControl's goroutine had processed that closure yet.
func TestRealitySessionCloseJoinsWatchControl(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()

	rec := &rawEventRecorder{}
	s := newRealitySession(rec.record)
	s.useControl(newBlockingReadConn(a, 150*time.Millisecond))

	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("Close returned after %v, want >= 100ms — watchControl was not joined", elapsed)
	}

	// #98: Close must also surface how long that wait actually took.
	d, ok := rec.drainDuration("reality: session close drained control-conn goroutine in ")
	if !ok {
		t.Fatal("Close did not emit a drain-duration event")
	}
	if d < 100*time.Millisecond {
		t.Fatalf("reported drain duration = %v, want >= 100ms to match the forced delay", d)
	}
}

// startStallingOrigin accepts one TCP connection and holds it open for delay
// without ever writing TLS bytes, so a client's handshake against it takes at
// least delay to fail. Used to give warmMimicCert a controllable lifetime.
func startStallingOrigin(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(delay)
	}()
	return ln.Addr().String()
}

// TestRealityCloseJoinsBackgroundGoroutines is the #65 acceptance test at the
// transport level: close must not return until acceptLoop and warmMimicCert have
// actually exited. warmMimicCert is given a deliberately slow origin so its
// lifetime is controllable; before the fix, close returned as soon as the
// listener was down, regardless of that still-running goroutine.
func TestRealityCloseJoinsBackgroundGoroutines(t *testing.T) {
	originAddr := startStallingOrigin(t, 300*time.Millisecond)

	rec := &rawEventRecorder{}
	resp, err := newRealityTransport(Config{RealityListen: "127.0.0.1:0", RealityProbeOrigin: originAddr}, rec.record)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.ensureListener(); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := resp.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("close returned after %v, want >= 200ms — warmMimicCert was not joined", elapsed)
	}

	// #98: close must also surface how long that wait actually took.
	d, ok := rec.drainDuration("reality: transport stop drained background goroutines in ")
	if !ok {
		t.Fatal("close did not emit a drain-duration event")
	}
	if d < 200*time.Millisecond {
		t.Fatalf("reported drain duration = %v, want >= 200ms to match the forced delay", d)
	}
}

// TestRealityEnsureListenerHonorsClosed is the #101 regression test: a close()
// that beats the very first Accept's call to ensureListener must not be undone by
// it. Pre-#101, ensureListener never checked t.closed at all, so its sync.Once
// could still bind a fresh listener and spawn acceptLoop/warmMimicCert after
// close() had already flipped t.closed and returned — close() would have read
// t.ln as still nil (not yet published) and skipped closing it, and its
// wg.Wait() would have seen no spawned goroutines yet and returned immediately,
// leaking a listener and its goroutines past what the caller believed was a
// fully quiesced transport.
func TestRealityEnsureListenerHonorsClosed(t *testing.T) {
	resp, err := newRealityTransport(Config{RealityListen: "127.0.0.1:0", RealityProbeOrigin: realityProbeOff}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := resp.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := resp.ensureListener(); err == nil {
		t.Fatal("ensureListener after close: want an error, got nil")
	}

	resp.mu.Lock()
	ln := resp.ln
	resp.mu.Unlock()
	if ln != nil {
		t.Fatal("ensureListener bound a listener after close; want it left nil")
	}

	// Confirm nothing was spawned either: wg.Wait() must return immediately, not
	// hang on an acceptLoop/warmMimicCert that close() will never get to join.
	done := make(chan struct{})
	go func() {
		resp.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ensureListener spawned goroutines after close; wg never drained")
	}
}

// TestNewSelectsRealityTransport drives the public constructor: New must wire
// the factory (selecting reality, building its camouflage cert) and surface an
// unknown-transport error rather than panicking.
// TestRealityAcceptCloseNoLeak races each session's token registration (in the
// background answer goroutine) against its teardown, and asserts the responder's
// pending map fully drains. It guards the token-lifecycle race: whichever of
// answer/Close loses must still unregister the token.
func TestRealityAcceptCloseNoLeak(t *testing.T) {
	resp, err := newRealityTransport(Config{RealityListen: "127.0.0.1:0", RealityProbeOrigin: realityProbeOff}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.close()
	if err := resp.ensureListener(); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 300; i++ {
		dialerSig, accepterSig := newMemSignalerPair()
		sess, err := resp.Accept(context.Background(), accepterSig)
		if err != nil {
			t.Fatal(err)
		}
		// Deliver an offer so answer() proceeds to mint and register a token,
		// then close concurrently to race registration against teardown.
		go func() {
			_ = dialerSig.Send(context.Background(),
				SignalFrame{Kind: sigOffer, Data: mustJSON(realityOffer{Proto: realityName})})
		}()
		sess.Close()
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp.mu.Lock()
		n := len(resp.pending)
		resp.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending map leaked %d entries after Accept+Close cycles", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNewSelectsRealityTransport(t *testing.T) {
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:9"},
		Roles:        []string{RoleClient},
		Transport:    TransportReality,
	})
	if err != nil {
		t.Fatalf("New(reality client): %v", err)
	}
	if eng.transport.Name() != TransportReality {
		t.Fatalf("selected %q, want %q", eng.transport.Name(), TransportReality)
	}
	if _, err := New(Config{
		Coordinators: []string{"127.0.0.1:9"},
		Roles:        []string{RoleClient},
		Transport:    "bogus",
	}); err == nil {
		t.Fatal("New should reject an unknown transport")
	}
}

func TestNewTransportSelection(t *testing.T) {
	for _, name := range []string{"", TransportWebRTC} {
		tr, err := newTransport(Config{Transport: name}, nil)
		if err != nil {
			t.Fatalf("transport %q: %v", name, err)
		}
		if tr.Name() != TransportWebRTC {
			t.Fatalf("transport %q -> %q, want %q", name, tr.Name(), TransportWebRTC)
		}
	}
	tr, err := newTransport(Config{Transport: TransportReality, RealityListen: "127.0.0.1:0"}, nil)
	if err != nil {
		t.Fatalf("reality: %v", err)
	}
	if tr.Name() != TransportReality {
		t.Fatalf("reality -> %q, want %q", tr.Name(), TransportReality)
	}
	if rt, ok := tr.(*realityTransport); ok {
		_ = rt.close()
	}
	if _, err := newTransport(Config{Transport: "nope"}, nil); err == nil {
		t.Fatal("want an error for an unknown transport")
	}
}
