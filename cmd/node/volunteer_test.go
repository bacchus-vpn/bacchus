package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
)

// TestResolveRolesProducesEveryCombinationTheFlagsCanExpress pins the whole role matrix
// the two opt-ins can produce, including that each is reachable ALONE. The relay-only
// row is the load-bearing one: relay must be sayable without exit, because relay costs
// bandwidth and exit costs legal exposure, and bundling them means somebody who meant to
// donate the first accepts the second unread.
//
// Mutation check: make the relay branch append core.RoleExit too — the single bundled
// -volunteer this card originally proposed — and the "relay only" row goes red while
// every other row still passes.
func TestResolveRolesProducesEveryCombinationTheFlagsCanExpress(t *testing.T) {
	tests := []struct {
		name string
		role string
		v    volunteerRoles
		want []string
	}{
		{"default: client only, both opt-ins off", "client", volunteerRoles{}, []string{"client"}},
		{"relay only", "client", volunteerRoles{relay: true}, []string{"client", "relay"}},
		{"exit only", "client", volunteerRoles{exit: true}, []string{"client", "exit"}},
		{"both, chosen separately", "client", volunteerRoles{relay: true, exit: true}, []string{"client", "relay", "exit"}},
		{"an opt-in already named in -role collapses", "client,relay", volunteerRoles{relay: true}, []string{"client", "relay"}},
		{"a serve-only node can volunteer the other role", "relay", volunteerRoles{exit: true}, []string{"relay", "exit"}},
		{"blanks and whitespace in -role are dropped", " client , ,relay ", volunteerRoles{}, []string{"client", "relay"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveRoles(tc.role, tc.v)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("resolveRoles(%q, relay=%t exit=%t) = %v; want %v", tc.role, tc.v.relay, tc.v.exit, got, tc.want)
			}
		})
	}
}

// TestVolunteerRelayNeverTurnsOnTheExitRole states the ruling this card implements once
// on its own, rather than only as a row in a table: donating bandwidth must not confer
// the exit's legal exposure as a side effect. Nothing about -volunteer-relay may produce
// the exit role.
//
// Mutation check: give the two opt-ins one shared bool, or add core.RoleExit to the
// relay branch, and this goes red on its own.
func TestVolunteerRelayNeverTurnsOnTheExitRole(t *testing.T) {
	for _, roleList := range []string{"client", "client,relay", "relay", ""} {
		for _, r := range resolveRoles(roleList, volunteerRoles{relay: true}) {
			if r == core.RoleExit {
				t.Fatalf("resolveRoles(%q, relay-only) produced the exit role: %v", roleList, resolveRoles(roleList, volunteerRoles{relay: true}))
			}
		}
	}
}

// TestValidateVolunteerDefaultsToDonatingNothing pins the default-off state at the
// validation layer: with neither opt-in set, nothing is required, nothing is warned
// about, and nothing about the node changes.
//
// Mutation check: default either flag to true in main.go, or hoist any check out of its
// `if c.roles.*` guard, and this goes red.
func TestValidateVolunteerDefaultsToDonatingNothing(t *testing.T) {
	warn, err := validateVolunteer(volunteerCheck{})
	if err != nil {
		t.Fatalf("validateVolunteer of the zero config: %v; a node that donates nothing needs nothing", err)
	}
	if len(warn) != 0 {
		t.Errorf("validateVolunteer of the zero config warned %q; a non-volunteer has nothing to warn about", warn)
	}
}

// TestValidateVolunteerRefusesWhatCannotWork covers every early refusal, each asserted
// on the substring that names the flag the operator actually typed. The failure being
// prevented is the quiet one: each of these registers a node that looks healthy from the
// inside and serves nobody.
//
// Mutation check: delete any one guard and its rows go red. Collapse the messages to a
// shared "invalid volunteer configuration" and every wantMsg goes red while the
// error/no-error shape still passes — which is the point of asserting on the message.
func TestValidateVolunteerRefusesWhatCannotWork(t *testing.T) {
	const key = "5aa1f1b0c0de5aa1f1b0c0de5aa1f1b0c0de5aa1f1b0c0de5aa1f1b0c0de1234"
	tests := []struct {
		name    string
		check   volunteerCheck
		wantMsg string
	}{
		{
			"exit without -advertise",
			volunteerCheck{roles: volunteerRoles{exit: true}, exitKeyHex: key},
			"-volunteer-exit requires -advertise",
		},
		{
			"exit without -exit-key",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "203.0.113.4:20000"},
			"-volunteer-exit requires -exit-key",
		},
		{
			"exit advertising a wildcard address",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "0.0.0.0:20000", exitKeyHex: key},
			"wildcard",
		},
		{
			"exit advertising loopback",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "127.0.0.1:20000", exitKeyHex: key},
			"loopback",
		},
		{
			"exit advertising IPv6 loopback",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "[::1]:20000", exitKeyHex: key},
			"loopback",
		},
		{
			"exit advertising a link-local address",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "169.254.7.7:20000", exitKeyHex: key},
			"link-local",
		},
		{
			"exit advertising a bare port",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "20000", exitKeyHex: key},
			"must be host:port",
		},
		{
			"exit advertising a port with no host",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: ":20000", exitKeyHex: key},
			"names no host",
		},
		{
			"exit advertising port 0",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "203.0.113.4:0", exitKeyHex: key},
			"not a port a relay can dial",
		},
		{
			"exit advertising a named port",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "203.0.113.4:https", exitKeyHex: key},
			"not a port a relay can dial",
		},
		{
			"relay carrying onion layers without a persistent key",
			volunteerCheck{roles: volunteerRoles{relay: true}, relayIngress: ":20001"},
			"-volunteer-relay with -relay-ingress requires -exit-key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateVolunteer(tc.check)
			if err == nil {
				t.Fatalf("validateVolunteer(%+v) accepted a configuration that cannot serve anyone", tc.check)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("message does not name what to fix:\n got: %v\nwant substring: %q", err, tc.wantMsg)
			}
		})
	}
}

// TestVolunteerRelayOnlyRequiresNothingBeyondTheOptIn is the ruling on the validation
// side. Relay is the option most home connections can safely take, and it is reachable
// behind NAT as a client's first hop without a forwarded port, so demanding an exit's
// -advertise or -exit-key of it would put the exit's setup cost on a bandwidth-only
// donor and push them toward the choice they should not be making by accident.
//
// Mutation check: hoist either exit check out of `if c.roles.exit` and this goes red.
func TestVolunteerRelayOnlyRequiresNothingBeyondTheOptIn(t *testing.T) {
	warn, err := validateVolunteer(volunteerCheck{roles: volunteerRoles{relay: true}, limitsDeclared: true})
	if err != nil {
		t.Fatalf("relay-only was refused: %v", err)
	}
	if len(warn) != 0 {
		t.Errorf("relay-only warned %q; there is nothing wrong with it", warn)
	}
}

// TestValidateVolunteerWarnsWithoutRefusing covers the configurations that are usually a
// mistake but are legitimately used somewhere, so they warn and serve rather than
// stopping the node.
//
// Mutation check: turn any of these into a fatal error and its row goes red — which is
// the regression that breaks a lab, a tunnelled uplink, or an exit reached by name.
// Delete a warning instead and the row goes red on the empty warning list.
func TestValidateVolunteerWarnsWithoutRefusing(t *testing.T) {
	const key = "5aa1f1b0c0de5aa1f1b0c0de5aa1f1b0c0de5aa1f1b0c0de5aa1f1b0c0de1234"
	tests := []struct {
		name     string
		check    volunteerCheck
		wantWarn string
	}{
		{
			"exit advertising private space",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "192.168.1.50:20000", exitKeyHex: key, limitsDeclared: true},
			"private address",
		},
		{
			"exit advertising carrier-NAT space",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "100.80.1.2:20000", exitKeyHex: key, limitsDeclared: true},
			"carrier-grade NAT",
		},
		{
			"exit advertising a name rather than an address",
			volunteerCheck{roles: volunteerRoles{exit: true}, advertise: "exit.example:20000", exitKeyHex: key, limitsDeclared: true},
			"name rather than an address",
		},
		{
			"volunteering with no declared limits",
			volunteerCheck{roles: volunteerRoles{relay: true}},
			"no declared limits",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			warn, err := validateVolunteer(tc.check)
			if err != nil {
				t.Fatalf("validateVolunteer refused a configuration that does work somewhere: %v", err)
			}
			var joined string
			if len(warn) > 0 {
				joined = strings.Join(warn, "\n")
			}
			if !strings.Contains(joined, tc.wantWarn) {
				t.Errorf("warnings do not mention the problem:\n got: %q\nwant substring: %q", joined, tc.wantWarn)
			}
		})
	}
}

// TestValidateVolunteerAcceptsAWellFormedExit is the positive case, so the refusals
// above are not passing merely because everything is refused.
//
// Mutation check: tighten checkAdvertise to reject anything that is not in a hard-coded
// allowlist and this goes red.
func TestValidateVolunteerAcceptsAWellFormedExit(t *testing.T) {
	const key = "5aa1f1b0c0de5aa1f1b0c0de5aa1f1b0c0de5aa1f1b0c0de5aa1f1b0c0de1234"
	// RFC 5737 / RFC 3849 documentation space, standing in for a real public address.
	for _, advertise := range []string{"203.0.113.4:20000", "[2001:db8::4]:20000"} {
		warn, err := validateVolunteer(volunteerCheck{
			roles:          volunteerRoles{relay: true, exit: true},
			advertise:      advertise,
			exitKeyHex:     key,
			limitsDeclared: true,
		})
		if err != nil {
			t.Errorf("validateVolunteer(-advertise %s) = %v; want accepted", advertise, err)
		}
		if len(warn) != 0 {
			t.Errorf("validateVolunteer(-advertise %s) warned %q; a public address is what it asked for", advertise, warn)
		}
	}
}

// TestVolunteerStringCarriesTheExitCost checks the startup line an operator reads back.
// It is the last place the exit choice is visible before the node starts carrying
// traffic, so it may not say "exit" without saying whose address that traffic leaves
// under — and relay-only has to say plainly that it does not egress, because "relay" on
// its own reads to most people as "carrying traffic out".
//
// Mutation check: shorten either line to just the role names and this goes red.
func TestVolunteerStringCarriesTheExitCost(t *testing.T) {
	exit := volunteerRoles{exit: true}.String()
	for _, want := range []string{"YOUR IP", "jurisdiction"} {
		if !strings.Contains(exit, want) {
			t.Errorf("the exit startup line %q does not mention %q", exit, want)
		}
	}
	if relay := (volunteerRoles{relay: true}).String(); !strings.Contains(relay, "does NOT egress") {
		t.Errorf("the relay-only startup line %q does not say it does not egress other people's traffic", relay)
	}
	if none := (volunteerRoles{}).String(); none != "nothing" {
		t.Errorf("volunteerRoles{}.String() = %q; want \"nothing\"", none)
	}
}

// fakeClientEngine stands in for *core.Engine in the client-half tests: no coordinator,
// no exit, no WebRTC handshake — just the Connect outcomes, in order, with the last
// repeated once the list is spent.
type fakeClientEngine struct {
	errs []error
	n    int
	done chan struct{}
}

func (f *fakeClientEngine) Connect(context.Context) error {
	i := f.n
	f.n++
	if i >= len(f.errs) {
		i = len(f.errs) - 1
	}
	return f.errs[i]
}

func (f *fakeClientEngine) Done() <-chan struct{} { return f.done }

func noBackoff(int) time.Duration { return 0 }

// testCtx bounds every retry test, so a regression that retries where it should return
// fails on the assertion rather than hanging the package.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestServingNodeKeepsServingThroughAClientConnectFailure is this card's design note,
// re-checked against current main and still true there: runNode returned as soon as the
// client half could not connect, and main turned that into log.Fatal, so a donated
// node's relay/exit died because of a fault on its own consumer side. The two halves
// fail for unrelated reasons — "every exit in the country I asked for is busy" says
// nothing about whether this node can still carry other people's traffic.
//
// Mutation check: change clientHalf.run to `return err` unconditionally — today's
// behaviour — and this goes red on the first attempt.
func TestServingNodeKeepsServingThroughAClientConnectFailure(t *testing.T) {
	busy := errors.New("country busy: every exit there is at capacity or out of quota")
	eng := &fakeClientEngine{errs: []error{busy, busy, nil}, done: make(chan struct{})}
	c := clientHalf{eng: eng, serving: true, backoff: noBackoff}

	if err := c.run(testCtx(t)); err != nil {
		t.Fatalf("run returned %v; a node that also serves must ride out its own client-side failure", err)
	}
	if eng.n != 3 {
		t.Errorf("Connect called %d times; want 3 — two failures retried in place, then success", eng.n)
	}
}

// TestPureClientStillFailsOnAConnectFailure is the other half of that seam. For a node
// that only clients, the connect failing IS the node failing, and turning that into a
// silent retry loop would hide a real error behind a process that looks alive. Today's
// behaviour, unchanged.
//
// Mutation check: drop the `if !c.serving` early return and this goes red — run keeps
// retrying and returns errNodeStopped at the context deadline instead of the error.
func TestPureClientStillFailsOnAConnectFailure(t *testing.T) {
	boom := errors.New("admission refused")
	eng := &fakeClientEngine{errs: []error{boom}, done: make(chan struct{})}
	c := clientHalf{eng: eng, serving: false, backoff: noBackoff}

	if err := c.run(testCtx(t)); !errors.Is(err, boom) {
		t.Fatalf("run returned %v; a client-only node must surface %v", err, boom)
	}
	if eng.n != 1 {
		t.Errorf("Connect called %d times; want 1 — a client-only node does not retry here", eng.n)
	}
}

// TestServingNodeHandsBackAnUnreachablePoolWhileMeshWalkCanRecover keeps the one failure
// runNode can still do something better about. Rebuilding against coordinators
// rediscovered through a peer beats retrying against addresses that have stopped
// answering, so this error is returned rather than swallowed.
//
// Mutation check: drop the meshOn guard and this goes red — run retries in place, the
// mesh-walk rebuild never happens, and the node keeps dialling coordinators that are
// gone forever.
func TestServingNodeHandsBackAnUnreachablePoolWhileMeshWalkCanRecover(t *testing.T) {
	eng := &fakeClientEngine{errs: []error{core.ErrNoCoordinatorReachable}, done: make(chan struct{})}
	c := clientHalf{eng: eng, serving: true, meshOn: true, backoff: noBackoff}

	if err := c.run(testCtx(t)); !errors.Is(err, core.ErrNoCoordinatorReachable) {
		t.Fatalf("run returned %v; want it handed back for the mesh-walk rebuild", err)
	}
	if eng.n != 1 {
		t.Errorf("Connect called %d times; want 1 — the caller owns the retry in this case", eng.n)
	}
}

// TestServingNodeRetriesAnUnreachablePoolWhenMeshWalkIsUnavailable covers the same
// error with nothing better to fall back on — no couriers configured, or its recoveries
// already spent. There is still no reason to stop serving: a coordinator that restarts
// comes back, and the registrations resume with it.
//
// Mutation check: return on ErrNoCoordinatorReachable regardless of meshOn and this goes
// red. That is the case that kills a donated node whose coordinator restarts while it
// has no mesh peers configured — the common one, since -mesh-peers is opt-in.
func TestServingNodeRetriesAnUnreachablePoolWhenMeshWalkIsUnavailable(t *testing.T) {
	eng := &fakeClientEngine{errs: []error{core.ErrNoCoordinatorReachable, nil}, done: make(chan struct{})}
	c := clientHalf{eng: eng, serving: true, meshOn: false, backoff: noBackoff}

	if err := c.run(testCtx(t)); err != nil {
		t.Fatalf("run returned %v; with no mesh-walk available a serving node keeps trying", err)
	}
	if eng.n != 2 {
		t.Errorf("Connect called %d times; want 2 — one failure retried in place, then success", eng.n)
	}
}

// TestClientHalfStopsCleanlyOnShutdown: an interrupt or a stopped engine during a retry
// is not a failure, and runNode maps errNodeStopped onto a zero exit.
//
// Mutation check: return ctx.Err() or the last connect error instead, and runNode's
// errors.Is(err, errNodeStopped) branch stops firing — so interrupting a volunteer node
// while its client half is retrying exits non-zero and logs a fatal.
func TestClientHalfStopsCleanlyOnShutdown(t *testing.T) {
	down := errors.New("no exit available yet")

	t.Run("context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		eng := &fakeClientEngine{errs: []error{down}, done: make(chan struct{})}
		c := clientHalf{eng: eng, serving: true, backoff: func(int) time.Duration {
			cancel() // the interrupt lands while the retry is waiting
			return time.Hour
		}}
		if err := c.run(ctx); !errors.Is(err, errNodeStopped) {
			t.Fatalf("run returned %v; want errNodeStopped so runNode exits cleanly", err)
		}
	})

	t.Run("engine stopped underneath", func(t *testing.T) {
		done := make(chan struct{})
		eng := &fakeClientEngine{errs: []error{down}, done: done}
		c := clientHalf{eng: eng, serving: true, backoff: func(int) time.Duration {
			close(done)
			return time.Hour
		}}
		if err := c.run(testCtx(t)); !errors.Is(err, errNodeStopped) {
			t.Fatalf("run returned %v; want errNodeStopped", err)
		}
	})
}

// TestClientRetryBackoffGrowsAndIsCapped: the retry is the node's own use of the
// network, which nobody but its operator is waiting on, so it backs off — and it is
// capped, so a node that has been failing for a week still checks every ten minutes
// instead of once a month.
//
// Mutation check: return a constant and the growth rows go red; remove the ceiling and
// the capped rows go red (attempt 20 would be about four months).
func TestClientRetryBackoffGrowsAndIsCapped(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 15 * time.Second},
		{1, 30 * time.Second},
		{2, time.Minute},
		{5, 8 * time.Minute},
		{6, 10 * time.Minute},
		{20, 10 * time.Minute},
	}
	for _, tc := range tests {
		if got := clientRetryBackoff(tc.attempt); got != tc.want {
			t.Errorf("clientRetryBackoff(%d) = %s; want %s", tc.attempt, got, tc.want)
		}
	}
}

// TestCoreEngineSatisfiesClientEngine keeps the test seam honest: the interface the
// retry policy is tested against has to be the one runNode actually passes a live engine
// through, or every test above is exercising a shape nothing uses.
//
// Mutation check: change either method's signature on the interface and this stops
// compiling.
func TestCoreEngineSatisfiesClientEngine(t *testing.T) {
	var _ clientEngine = (*core.Engine)(nil)
}
