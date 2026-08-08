package appstate

import (
	"errors"
	"testing"
)

// The gate that decides whether the GUI volunteer toggles are offered at all
// (bacchus#109, ADR-0053).
//
// The card this closes is a state that nobody chose: bacchus#37 gave Linux an
// Enforcer, and because the refusal was keyed on "does this build route the
// device" rather than on "can it serve while it does", volunteering became
// reachable on no platform that ships. The tests below pin the distinction that
// fixes it, in both directions — a platform that CAN must offer it, and a
// platform that CANNOT must still refuse.

// TestVolunteeringIsRefusedOnlyWhereTheCarveOutIsMissing walks the three
// postures a build can have. The middle row is bacchus#37's regression and the
// last is what ADR-0053 changes.
func TestVolunteeringIsRefusedOnlyWhereTheCarveOutIsMissing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enf     *fakeEnforcer
		refused bool
		why     string
	}{
		{
			name:    "proxy-only build",
			enf:     nil,
			refused: false,
			why:     "there is no tunnel for served traffic to be caught by, so there is nothing to refuse",
		},
		{
			name:    "routes the device and cannot carve the egress out",
			enf:     &fakeEnforcer{servesWhileRouted: false},
			refused: true,
			why:     "other people's traffic would egress at the upstream exit's address under a disclosure saying otherwise",
		},
		{
			name:    "routes the device and can carve the egress out",
			enf:     &fakeEnforcer{servesWhileRouted: true},
			refused: false,
			why:     "the carve-out makes the exit disclosure true, which is the whole of what #109 asked for",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c *Controller
			if tc.enf == nil {
				c = newProxyOnlyController(Config{})
			} else {
				c = newEnforcedController(Config{}, tc.enf)
			}
			if got := c.VolunteeringRefused(); got != tc.refused {
				t.Errorf("VolunteeringRefused() = %v, want %v: %s", got, tc.refused, tc.why)
			}
		})
	}
}

// TestARoutedBuildWithTheCarveOutCanPlanAServingSession is #109 closing, at the
// seam that was refusing: the same config that produced ErrVolunteerWhileRouted
// on an enforced build now produces a plan.
//
// It also checks the plan is a REAL one rather than a bypassed check — the exit
// role, the advertised address and the key all have to survive, because
// PlanVolunteer returns a zero VolunteerPlan alongside every refusal and a gate
// that opened without populating it would look like success from the outside.
func TestARoutedBuildWithTheCarveOutCanPlanAServingSession(t *testing.T) {
	cfg := Config{
		VolunteerExit:      true,
		VolunteerAdvertise: "203.0.113.4:20000",
		VolunteerExitKey:   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}

	if _, err := PlanVolunteer(cfg, true); !errors.Is(err, ErrVolunteerWhileRouted) {
		t.Fatalf("PlanVolunteer(routed, no carve-out) = %v, want ErrVolunteerWhileRouted", err)
	}

	plan, err := PlanVolunteer(cfg, false)
	if err != nil {
		t.Fatalf("PlanVolunteer(routed, carve-out available) = %v, want a plan", err)
	}
	if !plan.Serving() {
		t.Error("the plan does not serve, so the toggles are still doing nothing")
	}
	if plan.Advertise != "203.0.113.4:20000" || plan.ListenAddr != ":20000" || plan.ExitKeyHex == "" {
		t.Errorf("plan = %+v, want the advertised address, the derived listen port and the key carried through", plan)
	}
}

// TestClearingOnSaveFollowsTheSameGate covers the save path. Before #109 a
// stored opt-in was cleared on any enforced build; now it must survive on one
// that can serve, or a Linux volunteer's setting is wiped every time they open
// the settings window.
func TestClearingOnSaveFollowsTheSameGate(t *testing.T) {
	stored := Config{VolunteerRelay: true, VolunteerExit: true}

	if got, changed := ClearVolunteeringIfRouted(stored, true); !changed || got.VolunteerRelay || got.VolunteerExit {
		t.Errorf("a build that cannot serve kept the opt-ins: %+v (changed=%v)", got, changed)
	}
	got, changed := ClearVolunteeringIfRouted(stored, false)
	if changed {
		t.Error("a build that CAN serve while routed cleared the user's opt-ins anyway")
	}
	if !got.VolunteerRelay || !got.VolunteerExit {
		t.Errorf("opt-ins = relay:%v exit:%v, want both kept", got.VolunteerRelay, got.VolunteerExit)
	}
}

// TestServedSourceHookIsWiredToTheEnforcer checks what core.Config is actually
// given. A nil hook is "bind nothing", which is right for a proxy-only build
// and wrong for an enforced one — a serving session whose engine binds nothing
// egresses through the tunnel, which is the failure this whole change exists to
// prevent.
func TestServedSourceHookIsWiredToTheEnforcer(t *testing.T) {
	if hook := newProxyOnlyController(Config{}).servedSourceHook(); hook != nil {
		t.Error("a proxy-only build wired a served-source hook; there is no tunnel and nothing to bind")
	}

	enf := &fakeEnforcer{servesWhileRouted: true, servedSource: "192.0.2.5"}
	hook := newEnforcedController(Config{}, enf).servedSourceHook()
	if hook == nil {
		t.Fatal("an enforced build wired no served-source hook, so core would bind nothing and serve through the tunnel")
	}
	if got := hook(); got != "192.0.2.5" {
		t.Errorf("hook() = %q, want the Enforcer's own answer", got)
	}
}

// TestStartEnforcementAsksForTheCarveOutOnlyWhenServing pins the translation
// into enforcement.Policy. ServeEgress is the one field there that WIDENS what
// the machine may do, so a session that never volunteered must not set it.
func TestStartEnforcementAsksForTheCarveOutOnlyWhenServing(t *testing.T) {
	for _, serving := range []bool{false, true} {
		enf := &fakeEnforcer{servesWhileRouted: true}
		c := newEnforcedController(Config{}, enf)
		if _, err := c.startEnforcement(serving, c.cfg.Coordinators); err != nil {
			t.Fatalf("startEnforcement(%v): %v", serving, err)
		}
		policy, _ := enf.lastPolicy(t)
		if policy.ServeEgress != serving {
			t.Errorf("Policy.ServeEgress = %v for a serving=%v session, want %v", policy.ServeEgress, serving, serving)
		}
	}
}
