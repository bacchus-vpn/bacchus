package main

import (
	"net"
	"testing"
)

// Shared helpers for the country-scoped assignment surface (issues #146/#147,
// ADR-0042).

// countryOf returns the coordinator-DERIVED country of a registered exit.
//
// It exists because a client can no longer name an exit — a connect names a COUNTRY
// and this coordinator picks inside it (#146). A test whose subject really is one
// specific exit therefore asks for that exit's country, which in these fixtures (one
// exit per country) selects exactly that exit. That keeps each pre-#146 test asserting
// about the same node it always did, rather than being rewritten into a different test.
//
// Where a fixture deliberately puts SEVERAL exits in one country, naming the country
// no longer names the exit — and those tests assert on the tier/refusal behaviour
// instead, never on which exit came back.
func countryOf(exitID string) string {
	mu.Lock()
	defer mu.Unlock()
	if e := exits[exitID]; e != nil {
		return e.country
	}
	return ""
}

// requestList drives a `list`, whose reply is now the per-country capacity map.
func requestList(from *net.UDPConn) {
	handle(wire{Type: "list"}, from.LocalAddr().(*net.UDPAddr))
}

// countryIn finds one country's entry in a list reply. found is false when the country
// is absent altogether, which is a different state from present-but-busy and must not
// be conflated with it: #147 depends on a full country still being listed so it can be
// labelled busy.
func countryIn(reply wire, cc string) (info countryInfo, found bool) {
	for _, c := range reply.Countries {
		if c.Country == cc {
			return c, true
		}
	}
	return countryInfo{}, false
}

// wantCountry asserts a country is present with the given exit/available counts, and
// that Busy agrees with Available — the aggregate a client renders must be internally
// consistent or two clients will draw different conclusions from one datagram.
func wantCountry(t *testing.T, reply wire, cc string, exits, available int) {
	t.Helper()
	info, ok := countryIn(reply, cc)
	if !ok {
		t.Fatalf("country %s absent from the list reply: %+v", cc, reply.Countries)
	}
	if info.Exits != exits || info.Available != available {
		t.Errorf("country %s = %d exits / %d available; want %d / %d", cc, info.Exits, info.Available, exits, available)
	}
	if info.Busy != (info.Available == 0) {
		t.Errorf("country %s reports Busy=%v with Available=%d — the aggregate contradicts itself", cc, info.Busy, info.Available)
	}
}

// connectCountry drives a connect for a country, the only thing a client may ask for.
func connectCountry(cc, mode string, from *net.UDPConn) {
	dialConnect(wire{Country: cc, Mode: mode}, from.LocalAddr().(*net.UDPAddr))
}

// dialConnect drives one connect through the real handler, stamping the per-connect
// idempotency key that every connect now carries (issue #1, ADR-0042 §2). m.Type is set
// here so a caller cannot forget it, and a nonce already present is left alone — that is
// how a test drives a RETRANSMIT, by sending the same one twice.
//
// It exists so no test has to remember the nonce. A connect without one is refused
// outright, so a call site that forgot it would not fail loudly as a protocol error; it
// would quietly become a test that asserts on a refusal, which is how a fixture stops
// exercising the thing it was written for. Routing every connect through one helper
// makes that impossible by construction. Tests whose subject IS the nonce build the
// datagram by hand.
func dialConnect(m wire, from *net.UDPAddr) {
	m.Type = "connect"
	if m.Nonce == "" {
		m.Nonce = randID()
	}
	handle(m, from)
}
