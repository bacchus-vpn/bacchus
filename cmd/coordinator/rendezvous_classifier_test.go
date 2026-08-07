package main

import (
	"encoding/binary"
	"math/rand"
	"testing"

	// Aliased: this binary already has a package-level `rendezvous` (the mux).
	corerv "github.com/bacchus-vpn/bacchus/core/rendezvous"
)

// TestTheTwoDTLSClassifiersAgree pins this binary's looksLikeDTLS against
// core/rendezvous.LooksLikeDTLS, which is what the client half classifies with
// (issue #175 slice 2, ADR-0062).
//
// There are two copies because this binary deliberately does not link core (see
// wire's doc in main.go), and two copies of a wire decision is exactly the shape
// that shipped the country protocol broken with both sides green: each was
// self-consistent, and together they did not work. The wire-contract tests pin the
// two `wire` structs field for field; this pins the two classifiers datagram for
// datagram, which is the other thing both sides have to agree on.
//
// A test-only import changes nothing about what the shipped binary links.
func TestTheTwoDTLSClassifiersAgree(t *testing.T) {
	var corpus [][]byte

	// Every DTLS ContentType across both record versions, at the header boundary and
	// one byte either side of it.
	for _, ct := range []byte{0, 19, 20, 21, 22, 23, 24, 25, 26, 0xfe, 0xff} {
		for _, ver := range [][2]byte{{0xfe, 0xff}, {0xfe, 0xfd}, {0xfe, 0xfc}, {0xff, 0xfd}, {0x03, 0x03}} {
			for _, n := range []int{0, 1, 3, 12, 13, 14, 64} {
				d := make([]byte, n)
				if n > 0 {
					d[0] = ct
				}
				if n > 2 {
					d[1], d[2] = ver[0], ver[1]
				}
				corpus = append(corpus, d)
			}
		}
	}

	// Every shape a JSON value may begin with (RFC 8259 §2), which is the set the
	// coordinator's polarity argument turns on.
	for _, s := range []string{
		`{"type":"connect","nonce":"abcdef0123456789"}`,
		`[1,2,3,4,5,6,7,8,9,10,11,12,13,14]`,
		`"a string long enough to clear the header"`,
		`  {"type":"hello","magic":"bacchus"}`,
		"\t\n\r{\"type\":\"list\"}", `1234567890123456`, `-1234567890.12345`,
		`true and then some padding`, `false and then padding`, `null with padding`,
	} {
		corpus = append(corpus, []byte(s))
	}

	// A STUN Binding Request, which shares its two leading zero bits with a DTLS
	// ContentType and is the reason the coordinator tests the magic cookie.
	stun := make([]byte, 20)
	binary.BigEndian.PutUint16(stun[0:2], 0x0001)
	binary.BigEndian.PutUint32(stun[4:8], 0x2112A442)
	corpus = append(corpus, stun)

	// And random noise, because the interesting disagreements are the ones nobody
	// thought to write down. Seeded, so a failure is reproducible.
	r := rand.New(rand.NewSource(20260807)) //nolint:gosec // corpus generation, not crypto
	for i := 0; i < 2000; i++ {
		d := make([]byte, r.Intn(40))
		_, _ = r.Read(d)
		corpus = append(corpus, d)
	}

	for _, d := range corpus {
		if got, want := looksLikeDTLS(d), corerv.LooksLikeDTLS(d); got != want {
			t.Fatalf("the two classifiers disagree on % x: cmd/coordinator says %v, core/rendezvous says %v", d, got, want)
		}
	}
}
