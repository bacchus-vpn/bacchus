package appstate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core"
)

// TEST-NET-3 (RFC 5737): documentation space, never a real Bacchus node, and the
// same range cmd/node's own help text and tests use.
const testAdvertise = "203.0.113.4:20000"

// testExitKey is a hex-SHAPED placeholder of the right length, not key material.
// Nothing validates it as a curve point — core clamps whatever 32 bytes it is
// given (exitKeyFromSeed) — so a repeating pattern is the clearest way to say
// "this is not a key anybody holds", and Repeat is how the length stays
// obviously correct rather than counted by hand.
var testExitKey = strings.Repeat("ab", 32)

// exitCfg is a Config that volunteers as an exit and satisfies every
// requirement, so a test that means to exercise ONE refusal can start from a
// passing config and break exactly the field it is about.
func exitCfg() Config {
	return Config{
		VolunteerExit:      true,
		VolunteerAdvertise: testAdvertise,
		VolunteerExitKey:   testExitKey,
	}
}

// TestPlanVolunteerDefaultsToClientOnly pins the default: a Config nobody has
// touched serves nothing, and plans exactly the core.Config.Roles this client
// passed literally before issue #12.
//
// This is the test that matters most for everyone who never opens the
// volunteering section, which is almost everybody. Both opt-ins off must be
// indistinguishable from the pre-#12 client, on a routed platform included —
// which is why deviceRouted is exercised as true here too.
//
// Mutation check: have PlanVolunteer append core.RoleRelay unconditionally
// instead of behind cfg.VolunteerRelay, and both subtests go red on the roles
// comparison. Return ErrVolunteerWhileRouted before the !Serving() early return
// and the routed subtest goes red.
func TestPlanVolunteerDefaultsToClientOnly(t *testing.T) {
	for _, routed := range []bool{false, true} {
		name := "proxy-only"
		if routed {
			name = "device-routed"
		}
		t.Run(name, func(t *testing.T) {
			plan, err := PlanVolunteer(Config{}, routed)
			if err != nil {
				t.Fatalf("PlanVolunteer(zero config, routed=%v) = %v, want no error: not volunteering must never fail, on any platform", routed, err)
			}
			if want := []string{core.RoleClient}; !reflect.DeepEqual(plan.Roles, want) {
				t.Errorf("roles = %v, want %v", plan.Roles, want)
			}
			if plan.Serving() {
				t.Error("Serving() = true for a config with both opt-ins off")
			}
			if plan.Advertise != "" || plan.ListenAddr != "" || plan.ExitKeyHex != "" {
				t.Errorf("advertise/listen/key = %q/%q/%q, want all empty", plan.Advertise, plan.ListenAddr, plan.ExitKeyHex)
			}
			if len(plan.Warnings) != 0 {
				t.Errorf("warnings = %v, want none", plan.Warnings)
			}
		})
	}
}

// TestPlanVolunteerRolesAreIndependent is the ruling itself, as a test: relay
// and exit are two opt-ins and neither one implies the other. The bundled
// single-switch shape the card originally proposed would show up here as the
// relay row carrying core.RoleExit.
//
// Mutation check: make cfg.VolunteerRelay also append core.RoleExit (the
// bundled "-volunteer") and the relay-only row goes red naming the extra role.
// Swap the two appends and the both-on row still passes while the two
// single-opt-in rows both go red — which is why all four combinations are here
// rather than just the interesting one.
func TestPlanVolunteerRolesAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   Config
		roles []string
	}{
		{"neither", Config{}, []string{core.RoleClient}},
		{"relay only", Config{VolunteerRelay: true}, []string{core.RoleClient, core.RoleRelay}},
		{"exit only", exitCfg(), []string{core.RoleClient, core.RoleExit}},
		{"both", func() Config { c := exitCfg(); c.VolunteerRelay = true; return c }(),
			[]string{core.RoleClient, core.RoleRelay, core.RoleExit}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := PlanVolunteer(tc.cfg, false)
			if err != nil {
				t.Fatalf("PlanVolunteer: %v", err)
			}
			if !reflect.DeepEqual(plan.Roles, tc.roles) {
				t.Errorf("roles = %v, want %v", plan.Roles, tc.roles)
			}
		})
	}
}

// TestPlanVolunteerRelayNeedsNothingBeyondTheOptIn is the other half of the
// ruling: a bandwidth-only donor is not asked for an exit's setup. Behind a home
// NAT a relay serves as a client's FIRST hop, reached the way the client itself
// is, so it needs no forwarded port and no fixed identity — and requiring them
// would put the exit's cost back on somebody who explicitly declined the exit.
//
// Mutation check: hoist the advertise or exit-key check above the
// `if !cfg.VolunteerExit` early return so it applies to any serving role, and
// this goes red. That mutation is the plausible one — it reads like tightening
// validation — which is why this is its own test rather than a row above.
func TestPlanVolunteerRelayNeedsNothingBeyondTheOptIn(t *testing.T) {
	plan, err := PlanVolunteer(Config{VolunteerRelay: true}, false)
	if err != nil {
		t.Fatalf("PlanVolunteer(relay only) = %v, want no error: the relay opt-in requires nothing else", err)
	}
	if !plan.Serving() {
		t.Error("Serving() = false for a relay volunteer")
	}
	// A relay is not an exit, so none of the exit's engine fields may be set —
	// core reads Advertise only for the exit role, but a relay plan that filled
	// them in would mean the two opt-ins had been conflated somewhere.
	if plan.Advertise != "" || plan.ListenAddr != "" || plan.ExitKeyHex != "" {
		t.Errorf("relay-only plan carries exit fields: advertise/listen/key = %q/%q/%q", plan.Advertise, plan.ListenAddr, plan.ExitKeyHex)
	}
}

// TestPlanVolunteerRefusesWhileDeviceRouted covers the refusal that is least
// guessable and most consequential — see ErrVolunteerWhileRouted for why
// serving and device-wide routing cannot both be true in one process. Both
// opt-ins are refused, not just the exit: a relay's forwarding is caught by the
// same default route, so it would spend this machine's own tunnel carrying
// somebody else's traffic.
//
// Mutation check: delete the deviceRouted guard and the two serving rows go red.
// Gate it on cfg.VolunteerExit instead of on plan.Serving() and the relay row
// alone goes red — which is the mutation worth catching, since "only the exit
// egresses, so only the exit can conflict" is the wrong intuition this test
// exists to disprove.
func TestPlanVolunteerRefusesWhileDeviceRouted(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"relay", Config{VolunteerRelay: true}},
		{"exit", exitCfg()},
		{"both", func() Config { c := exitCfg(); c.VolunteerRelay = true; return c }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := PlanVolunteer(tc.cfg, true)
			if !errors.Is(err, ErrVolunteerWhileRouted) {
				t.Fatalf("PlanVolunteer(%s, routed) = %v, want ErrVolunteerWhileRouted", tc.name, err)
			}
			// A refused plan must carry nothing: a caller that ignored the
			// error would otherwise build an engine with serve roles in it.
			if !reflect.DeepEqual(plan, VolunteerPlan{}) {
				t.Errorf("refused plan = %+v, want the zero VolunteerPlan", plan)
			}
		})
	}
}

// TestPlanVolunteerExitRefusals covers everything the exit opt-in is refused
// for, each asserted on the specific sentinel rather than on "some error", so a
// refusal cannot silently start reporting the wrong cause — the message is what
// tells the user which field to fix, and it is the only thing they get.
//
// Mutation check: delete any one guard in PlanVolunteer/classifyAdvertise and
// exactly the rows for it go red. Collapse ErrVolunteerAddressForm and
// ErrVolunteerAddressUnreachable into one sentinel and the two groups stop
// distinguishing "you typed it wrong" from "that address can never be dialed".
func TestPlanVolunteerExitRefusals(t *testing.T) {
	withAdvertise := func(a string) Config { c := exitCfg(); c.VolunteerAdvertise = a; return c }
	withKey := func(k string) Config { c := exitCfg(); c.VolunteerExitKey = k; return c }

	for _, tc := range []struct {
		name string
		cfg  Config
		want error
	}{
		{"no address at all", withAdvertise(""), ErrVolunteerExitNeedsAddress},
		{"whitespace-only address", withAdvertise("   "), ErrVolunteerExitNeedsAddress},

		{"not host:port", withAdvertise("203.0.113.4"), ErrVolunteerAddressForm},
		{"bare port", withAdvertise(":20000"), ErrVolunteerAddressForm},
		{"non-numeric port", withAdvertise("203.0.113.4:https"), ErrVolunteerAddressForm},
		{"zero port", withAdvertise("203.0.113.4:0"), ErrVolunteerAddressForm},
		{"port above range", withAdvertise("203.0.113.4:65536"), ErrVolunteerAddressForm},

		{"wildcard v4", withAdvertise("0.0.0.0:20000"), ErrVolunteerAddressUnreachable},
		{"wildcard v6", withAdvertise("[::]:20000"), ErrVolunteerAddressUnreachable},
		{"loopback v4", withAdvertise("127.0.0.1:20000"), ErrVolunteerAddressUnreachable},
		{"loopback v6", withAdvertise("[::1]:20000"), ErrVolunteerAddressUnreachable},
		{"link-local v4", withAdvertise("169.254.1.1:20000"), ErrVolunteerAddressUnreachable},
		{"link-local v6", withAdvertise("[fe80::1]:20000"), ErrVolunteerAddressUnreachable},

		{"no key", withKey(""), ErrVolunteerExitNeedsKey},
		{"whitespace-only key", withKey("  "), ErrVolunteerExitNeedsKey},
		{"key too short", withKey("abab"), ErrVolunteerExitKeyForm},
		{"key too long", withKey(testExitKey + "ab"), ErrVolunteerExitKeyForm},
		{"key not hex", withKey(strings.Repeat("z", 64)), ErrVolunteerExitKeyForm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := PlanVolunteer(tc.cfg, false)
			if !errors.Is(err, tc.want) {
				t.Fatalf("PlanVolunteer = %v, want %v", err, tc.want)
			}
			if !reflect.DeepEqual(plan, VolunteerPlan{}) {
				t.Errorf("refused plan = %+v, want the zero VolunteerPlan", plan)
			}
		})
	}
}

// TestPlanVolunteerAdvertiseWarnsAndServes is the other half of the
// classification: what is usually a mistake but is legitimately used somewhere
// must be reported and then HONORED. Refusing these would break a LAN, a lab, or
// a tunnelled uplink to catch a mistake a sentence already names.
//
// Mutation check: turn any of these three into a refusal and its row goes red on
// the error. Drop the warning while still serving and the same row goes red on
// the warnings comparison — both halves are asserted, because a silent
// warn-and-serve is indistinguishable from a working exit until nobody ever
// dials it.
func TestPlanVolunteerAdvertiseWarnsAndServes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		advertise string
		want      string
	}{
		{"private v4", "192.168.1.5:20000", WarnVolunteerAddressPrivate},
		{"private 10/8", "10.1.2.3:20000", WarnVolunteerAddressPrivate},
		{"carrier-grade NAT", "100.64.1.2:20000", WarnVolunteerAddressCGNAT},
		{"a name, not an address", "exit.example.com:20000", WarnVolunteerAddressName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := exitCfg()
			cfg.VolunteerAdvertise = tc.advertise
			plan, err := PlanVolunteer(cfg, false)
			if err != nil {
				t.Fatalf("PlanVolunteer(%s) = %v, want warn-and-serve, not a refusal", tc.advertise, err)
			}
			if !reflect.DeepEqual(plan.Warnings, []string{tc.want}) {
				t.Fatalf("warnings = %v, want exactly %q", plan.Warnings, tc.want)
			}
			// Served, not just warned: the exit role and its engine fields are
			// all present.
			if !plan.Serving() || plan.Advertise != tc.advertise || plan.ExitKeyHex != testExitKey {
				t.Errorf("warned plan did not serve: %+v", plan)
			}
		})
	}
}

// TestPlanVolunteerCarrierNATIsNotClassifiedAsPrivate guards the one
// classification a reader is most likely to "simplify" away: 100.64.0.0/10 is
// NOT covered by net.IP.IsPrivate, and it needs its own message because the
// remedy is different — there is no port to forward at all, so relay-only is the
// answer rather than "advertise your public address instead".
//
// Mutation check: delete the cgnat check and this goes red with the private-space
// warning, since 100.64.1.2 then falls through to the no-warning case (proving
// IsPrivate really does not cover it).
func TestPlanVolunteerCarrierNATIsNotClassifiedAsPrivate(t *testing.T) {
	cfg := exitCfg()
	cfg.VolunteerAdvertise = "100.64.1.2:20000"
	plan, err := PlanVolunteer(cfg, false)
	if err != nil {
		t.Fatalf("PlanVolunteer: %v", err)
	}
	if !reflect.DeepEqual(plan.Warnings, []string{WarnVolunteerAddressCGNAT}) {
		t.Fatalf("warnings for carrier-NAT space = %v, want exactly the carrier-NAT warning", plan.Warnings)
	}
}

// TestPlanVolunteerPublicAddressWarnsAboutNothing is the negative control for
// the two tests above: a warning set that is never empty is a warning set nobody
// reads.
//
// Mutation check: make classifyAdvertise return a warning unconditionally and
// this goes red.
func TestPlanVolunteerPublicAddressWarnsAboutNothing(t *testing.T) {
	plan, err := PlanVolunteer(exitCfg(), false)
	if err != nil {
		t.Fatalf("PlanVolunteer: %v", err)
	}
	if len(plan.Warnings) != 0 {
		t.Errorf("warnings for %s = %v, want none", testAdvertise, plan.Warnings)
	}
}

// TestPlanVolunteerDerivesListenAddrFromTheAdvertisedPort pins the one place
// this deliberately does not mirror cmd/node, which takes -listen and -advertise
// as independent flags and so lets them disagree. An exit that advertises one
// port and listens on another registers something nothing can reach; here that
// is unrepresentable.
//
// A non-default port is used on purpose: cmd/node defaults -listen to ":20000",
// so a mutation that hardcoded that value would pass against an advertised
// :20000 and be invisible.
//
// Mutation check: return a fixed ":20000" from PlanVolunteer, or leave
// ListenAddr empty (core then hands "" to net.Listen and binds an OS-assigned
// port the advertised one does not match), and this goes red.
func TestPlanVolunteerDerivesListenAddrFromTheAdvertisedPort(t *testing.T) {
	cfg := exitCfg()
	cfg.VolunteerAdvertise = "203.0.113.4:41234"
	plan, err := PlanVolunteer(cfg, false)
	if err != nil {
		t.Fatalf("PlanVolunteer: %v", err)
	}
	if plan.ListenAddr != ":41234" {
		t.Errorf("ListenAddr = %q, want %q — the listen port must come from the advertised one", plan.ListenAddr, ":41234")
	}
	if plan.Advertise != "203.0.113.4:41234" {
		t.Errorf("Advertise = %q, want it unchanged", plan.Advertise)
	}
}

// TestPlanVolunteerTrimsBeforeDeciding covers the whitespace seam the same way
// ValidateRelayChainConfig's own test does. Two distinct failures live here: a
// whitespace-only address must read as ABSENT (so the user is told what to
// provide) rather than as malformed, and a padded but valid address must be
// persisted and passed to core trimmed — core compares Advertise as a string, so
// " 203.0.113.4:20000" is not the endpoint the coordinator observes.
//
// Mutation check: drop either TrimSpace in PlanVolunteer and this goes red — the
// first case reports ErrVolunteerAddressForm instead of
// ErrVolunteerExitNeedsAddress, and the second carries the padding into
// core.Config.
func TestPlanVolunteerTrimsBeforeDeciding(t *testing.T) {
	t.Run("padded values are trimmed", func(t *testing.T) {
		cfg := exitCfg()
		cfg.VolunteerAdvertise = "  " + testAdvertise + "  "
		cfg.VolunteerExitKey = "\t" + testExitKey + "\n"
		plan, err := PlanVolunteer(cfg, false)
		if err != nil {
			t.Fatalf("PlanVolunteer: %v", err)
		}
		if plan.Advertise != testAdvertise {
			t.Errorf("Advertise = %q, want %q", plan.Advertise, testAdvertise)
		}
		if plan.ExitKeyHex != testExitKey {
			t.Errorf("ExitKeyHex = %q, want it trimmed", plan.ExitKeyHex)
		}
	})
	t.Run("whitespace-only key reads as absent, not malformed", func(t *testing.T) {
		cfg := exitCfg()
		cfg.VolunteerExitKey = "   "
		if _, err := PlanVolunteer(cfg, false); !errors.Is(err, ErrVolunteerExitNeedsKey) {
			t.Fatalf("PlanVolunteer = %v, want ErrVolunteerExitNeedsKey", err)
		}
	})
}

// TestPlanVolunteerProducesAConfigCoreAccepts closes the loop that no amount of
// checking inside this package can: it builds the core.Config
// Controller.connectAsync builds and hands it to the real core.New.
//
// Every refusal above exists to pre-empt one of core's own construction errors,
// and a mirrored check is only worth having if the thing it mirrors still agrees
// with it. core.New refuses an exit role without Advertise, and refuses an
// ExitKeyHex that is not 32 bytes of hex — so if this package's idea of a
// complete exit config ever drifts from core's, this fails here rather than in a
// user's connect.
//
// Mutation check: stop setting Advertise in VolunteerPlan and this fails with
// core's "exit role requires Advertise host:port"; corrupt ExitKeyHex and it
// fails with core's own hex refusal.
func TestPlanVolunteerProducesAConfigCoreAccepts(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"client only", Config{}},
		{"relay", Config{VolunteerRelay: true}},
		{"exit", exitCfg()},
		{"both", func() Config { c := exitCfg(); c.VolunteerRelay = true; return c }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := PlanVolunteer(tc.cfg, false)
			if err != nil {
				t.Fatalf("PlanVolunteer: %v", err)
			}
			// Nothing is dialled or bound by core.New — the exit listener and
			// the registrations come up in Start, which this deliberately does
			// not call. The coordinator address is TEST-NET-3 and never
			// contacted.
			eng, err := core.New(core.Config{
				Coordinators: []string{"203.0.113.10:8080"},
				Roles:        plan.Roles,
				SocksAddr:    SocksAddr,
				Advertise:    plan.Advertise,
				ListenAddr:   plan.ListenAddr,
				ExitKeyHex:   plan.ExitKeyHex,
			})
			if err != nil {
				t.Fatalf("core.New refused the plan this client would build: %v", err)
			}
			eng.Stop()
		})
	}
}

// TestVolunteerConfigFieldsUseStableJSONKeys writes the four keys out rather
// than round-tripping through the same struct, which would pass under any
// renaming. These are a persisted file format: renaming a tag silently discards
// what a user already saved, and for VolunteerExitKey that means silently
// discarding their exit's IDENTITY — they come back as a node nobody's cached
// directory can reach.
//
// Mutation check: rename any tag (volunteerExitKey -> volunteer_exit_key, say)
// and its row goes red.
func TestVolunteerConfigFieldsUseStableJSONKeys(t *testing.T) {
	b, err := json.Marshal(exitCfg())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{
		"volunteerRelay",
		"volunteerExit",
		"volunteerAdvertise",
		"volunteerExitKey",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("config JSON has no %q key; got %v", key, sortedKeys(raw))
		}
	}
}

// TestVolunteerConfigRoundTrips is the persistence half: a choice made in the
// dialog survives being written and read back. Both booleans are set true so
// the test cannot pass on Go's zero values.
//
// Mutation check: remove any of the four json tags and its field round-trips to
// its zero value, failing the comparison — which for the two booleans means a
// volunteer silently stops volunteering at the next launch.
func TestVolunteerConfigRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bacchus-fyne.config.json")
	want := Config{
		Coordinators:       []string{"203.0.113.10:8080"}, // TEST-NET-3 (RFC 5737)
		VolunteerRelay:     true,
		VolunteerExit:      true,
		VolunteerAdvertise: testAdvertise,
		VolunteerExitKey:   testExitKey,
	}
	if err := SaveConfig(path, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got Config
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed the config:\n got %+v\nwant %+v", got, want)
	}
}

// TestVolunteerOptInsDefaultToOffInAStoredConfig covers the upgrade path
// explicitly: a config file written before #12 has neither key, and must load as
// not volunteering. This is a different claim from the zero-value test above —
// it is about what json.Unmarshal does to a file that predates the fields, which
// is how every existing user's config will arrive.
//
// Mutation check: give either field a non-zero meaning (an inverted
// `volunteerRelayDisabled` bool, say) and this goes red — that shape would turn
// every pre-#12 config into a volunteer at the next launch, without anybody
// having agreed to anything.
func TestVolunteerOptInsDefaultToOffInAStoredConfig(t *testing.T) {
	// A pre-#12 config file, verbatim in the shape settings.go was already
	// writing.
	const pre12 = `{"coordinators":["203.0.113.10:8080"],"dns":"1.1.1.1:53","autoConnect":true}`
	var got Config
	if err := json.Unmarshal([]byte(pre12), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.VolunteerRelay || got.VolunteerExit {
		t.Fatalf("a config predating issue #12 loaded as volunteering: relay=%v exit=%v", got.VolunteerRelay, got.VolunteerExit)
	}
	plan, err := PlanVolunteer(got, false)
	if err != nil {
		t.Fatalf("PlanVolunteer: %v", err)
	}
	if plan.Serving() {
		t.Error("a config predating issue #12 planned a serving role")
	}
}

// TestNewExitKeyHexIsAcceptedByItsOwnValidator asserts the generator and the
// validator agree, which is the only way the Generate button can be trusted: a
// button that produces a value the same dialog then refuses is worse than no
// button.
//
// Mutation check: change exitKeyHexLen, or have NewExitKeyHex read fewer than 32
// bytes, and this goes red. Return a constant and the distinctness check goes
// red — an exit identity every installation shares is not an identity.
func TestNewExitKeyHexIsAcceptedByItsOwnValidator(t *testing.T) {
	first, err := NewExitKeyHex()
	if err != nil {
		t.Fatalf("NewExitKeyHex: %v", err)
	}
	if len(first) != exitKeyHexLen {
		t.Errorf("generated key is %d chars, want %d", len(first), exitKeyHexLen)
	}
	if !validExitKeyHex(first) {
		t.Errorf("generated key %q is refused by validExitKeyHex", first)
	}
	// And it reaches core intact through the same path a user's typed key does.
	cfg := exitCfg()
	cfg.VolunteerExitKey = first
	plan, err := PlanVolunteer(cfg, false)
	if err != nil {
		t.Fatalf("PlanVolunteer with a generated key: %v", err)
	}
	if plan.ExitKeyHex != first {
		t.Errorf("ExitKeyHex = %q, want the generated key", plan.ExitKeyHex)
	}

	second, err := NewExitKeyHex()
	if err != nil {
		t.Fatalf("NewExitKeyHex (second): %v", err)
	}
	if first == second {
		t.Error("two calls to NewExitKeyHex returned the same key")
	}
}
