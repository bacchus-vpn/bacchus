//go:build linux

package enforcement

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/bacchus-vpn/bacchus/cmd/bacchus-netd/netdwire"
)

// pointAtNothing aims the client at a socket path with no helper behind it, for
// the whole of one test.
func pointAtNothing(t *testing.T) {
	t.Helper()
	old := netdSocket
	netdSocket = filepath.Join(t.TempDir(), "netd.sock")
	t.Cleanup(func() { netdSocket = old })
}

// New now returns a real Enforcer. This replaces the NotImplementedError
// contract this file used to pin: bacchus#37 is what makes Linux an enforcing
// platform, so "New refuses" stopped being the correct behaviour the moment the
// helper existed.
func TestNewReturnsARealEnforcer(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	if e == nil {
		t.Fatal("New() Enforcer = nil, want a real one")
	}
	var notImpl NotImplementedError
	if errors.As(err, &notImpl) {
		t.Errorf("New() still returns NotImplementedError: %v", err)
	}
}

// New must NOT probe for the helper. If it did, DeviceEnforced() would become a
// property of the moment rather than of the platform, and — far worse — a
// machine whose socket-activated helper was slow to answer would fall back to
// "Proxy ready" and leave the user unprotected while the UI looked healthy.
// That is precisely the degradation parity item 7 exists to forbid.
func TestNewSucceedsWithNoHelperInstalled(t *testing.T) {
	pointAtNothing(t)

	e, err := New()
	if err != nil {
		t.Fatalf("New() error = %v, want nil even with no helper present", err)
	}
	if e == nil {
		t.Fatal("New() Enforcer = nil; DeviceEnforced() would go false and the UI would claim proxy-only")
	}
}

// The connect must fail, loudly and by a recognisable error, when the helper is
// unreachable. ADR-0049's Consequences: falling back to a working SOCKS proxy
// under a "Protected" banner is the failure this whole bar exists to rule out,
// and a missing helper is the most likely way to meet it on Linux.
func TestStartFailsWhenTheHelperIsUnreachable(t *testing.T) {
	pointAtNothing(t)

	e, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	sess, err := e.Start(Policy{Coordinators: []string{"192.0.2.1:443"}}, "127.0.0.1:1080")
	if err == nil {
		t.Fatal("Start() succeeded with no helper — the client would report Protected over an unrouted machine")
	}
	if sess != nil {
		t.Errorf("Start() returned a Session alongside its error: %v", sess)
	}
	if !errors.Is(err, ErrHelperUnreachable) {
		t.Errorf("Start() error = %v, want one wrapping ErrHelperUnreachable so the UI can name the fix", err)
	}
}

// Recover is a launch-time call and must be silent when the helper is missing.
// A user who has not installed it yet should be able to open the app.
func TestRecoverIsSilentWithNoHelper(t *testing.T) {
	pointAtNothing(t)

	e, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	e.Recover() // must not panic, block, or fail the launch
}

// ReserveUnderlay runs on the dial path before a session exists. With no
// helper it must be a silent no-op rather than an error or a panic: the
// transport pool calls it whether or not enforcement is up.
func TestReserveUnderlayWithNoHelperIsSilent(t *testing.T) {
	pointAtNothing(t)

	e, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	e.ReserveUnderlay("198.51.100.20")
}

func TestTranslateRefusalMapsCodesToActionableErrors(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{
		{netdwire.CodeBusy, ErrHelperBusy},
		{netdwire.CodeVersion, ErrHelperVersion},
		{netdwire.CodeDenied, ErrHelperUnreachable},
	} {
		got := translateRefusal(&netdwire.ProtocolError{Code: tc.code, Message: "refused"})
		if !errors.Is(got, tc.want) {
			t.Errorf("translateRefusal(%q) = %v, want one wrapping %v", tc.code, got, tc.want)
		}
	}

	// An unmapped code passes through unchanged rather than being flattened
	// into one of the three above: an internal failure is not a version skew,
	// and telling the user to reinstall would be wrong advice.
	other := &netdwire.ProtocolError{Code: netdwire.CodeInternal, Message: "netlink said no"}
	got := translateRefusal(other)
	if errors.Is(got, ErrHelperBusy) || errors.Is(got, ErrHelperVersion) || errors.Is(got, ErrHelperUnreachable) {
		t.Errorf("translateRefusal(internal) = %v, want it left alone", got)
	}
	if got.Error() != "netlink said no" {
		t.Errorf("translateRefusal(internal) message = %q, want it preserved", got.Error())
	}
}

// The error/no-error split in osnet.go is load bearing, and this is the check
// that it survived being reimplemented over a socket. Every silent method must
// stay silent when the transport is dead, and every fallible one must surface —
// swapping either direction changes the fail-closed posture (ADR-0049's osNet
// map).
func TestTransportFailurePreservesTheSilentFallibleSplit(t *testing.T) {
	pointAtNothing(t)
	o := &linuxOS{} // never connected: every request fails at the transport

	// Silent by contract. These must not panic and have no error to return;
	// the assertion is that they are callable and produce nothing.
	o.addExclusionRoutes([]string{"192.0.2.1/32"}, gatewayInfo{})
	o.addExclusionRoutesV6([]string{"2001:db8::1/128"}, gatewayInfo{})
	o.addInclusionRoutes([]string{"192.0.2.2/32"}, "10.66.0.2")
	o.removeRoutes([]string{"192.0.2.1/32"})
	o.disablePhysicalIPv6("eth0")
	o.enablePhysicalIPv6("eth0")
	o.disableKillSwitch()
	o.recoverKillSwitch()
	o.refreshKillSwitchAllowIP("192.0.2.9")

	// Fallible by contract: a dead transport must reach the caller, because
	// bring-up has to unwind rather than continue believing it worked.
	if _, err := o.defaultGateway(); err == nil {
		t.Error("defaultGateway() with a dead transport returned nil error")
	}
	if _, err := o.createTUN(); err == nil {
		t.Error("createTUN() with a dead transport returned nil error")
	}
	if err := o.configureTunInterface("10.66.0.2", 24); err == nil {
		t.Error("configureTunInterface() with a dead transport returned nil error")
	}
	if err := o.addSplitDefaultRoute("10.66.0.2"); err == nil {
		t.Error("addSplitDefaultRoute() with a dead transport returned nil error")
	}
	if err := o.enableKillSwitch([]string{"192.0.2.1"}, nil); err == nil {
		t.Error("enableKillSwitch() with a dead transport returned nil error — the client would report Protected over an unarmed machine")
	}
}
