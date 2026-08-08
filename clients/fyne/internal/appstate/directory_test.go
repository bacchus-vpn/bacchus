package appstate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/accountclient"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// testDirectory is a coordinator's half of the cold-start exchange, over a real
// loopback socket: a signing key, a per-user secret, a live coldstart.Serve, and
// the invite a client is handed out of band.
//
// It runs the REAL server rather than a stub of it because the half under test
// is a fetch, a signature check and an expiry check, and a stub would be free to
// agree with the client about all three. What this cannot cover is the blend
// onto the coordinator's TURN port (coldstart.Demux) — that is cmd/coordinator's
// and is tested there.
type testDirectory struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	addr   string
	invite string

	// snapshot is what the server hands out; swap it to move an address.
	snapshot []byte
}

func newTestDirectory(t *testing.T, entries ...coldstart.Entry) *testDirectory {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate snapshot key: %v", err)
	}
	d := &testDirectory{priv: priv, pub: pub}
	d.snapshot = d.sign(t, d.freshSnapshot(entries...))

	secretID, secret, err := coldstart.GenerateSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	store := coldstart.NewMemStore()
	store.Add(secretID, secret)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = coldstart.Serve(ctx, pc, store, func() []byte { return d.snapshot }) }()
	t.Cleanup(func() { cancel(); _ = pc.Close() })
	d.addr = pc.LocalAddr().String()

	d.invite, err = coldstart.EncodeInvite(coldstart.Invite{
		Coordinator: d.addr,
		SecretID:    secretID,
		Secret:      secret,
		PublicKey:   pub,
	})
	if err != nil {
		t.Fatalf("encode invite: %v", err)
	}
	return d
}

// freshSnapshot is a directory valid from now, with the coordinator's own
// five-minute TTL (cmd/coordinator's snapshotTTL).
func (d *testDirectory) freshSnapshot(entries ...coldstart.Entry) coldstart.Snapshot {
	now := time.Now()
	return coldstart.Snapshot{
		Version:   coldstart.SnapshotVersion,
		IssuedAt:  now,
		ExpiresAt: now.Add(5 * time.Minute),
		Entries:   entries,
	}
}

func (d *testDirectory) sign(t *testing.T, snap coldstart.Snapshot) []byte {
	t.Helper()
	signed, err := coldstart.Sign(d.priv, snap)
	if err != nil {
		t.Fatalf("sign snapshot: %v", err)
	}
	return signed
}

// useTempConfigDir points DefaultDirectoryCachePath at a scratch directory, so a
// test never reads or writes the running user's real cache.
func useTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir) // the same candidate on Windows
	return dir
}

// writeCache installs signed at the path AcquireDirectory reads.
func writeCache(t *testing.T, signed []byte) string {
	t.Helper()
	path := DefaultDirectoryCachePath()
	if path == "" {
		t.Fatal("this OS names no per-user config directory, so there is nowhere to cache a directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := coldstart.SaveCache(path, signed); err != nil {
		t.Fatal(err)
	}
	return path
}

func coordinatorEntry(addr string) coldstart.Entry {
	return coldstart.Entry{Role: "coordinator", ID: "coordinator", Addr: addr}
}

func accountEntry(url string) coldstart.Entry {
	return coldstart.Entry{Role: "account", ID: "account", Addr: url}
}

// ---------------------------------------------------------------------------
// The wire vocabulary
// ---------------------------------------------------------------------------

// TestDirectoryRolesMatchTheWire pins the two role strings this client reads
// against the literals the producer writes.
//
// cmd/coordinator's buildSnapshot is package main and importable from nowhere,
// so the two halves cannot share a constant; this is the consuming end of the
// pairing TestCountrySourceWireContract already establishes for the country
// provenance literals. Renaming either side without the other produces a client
// that verifies a perfectly good directory and then finds nothing in it — a
// silent fallback to the configured addresses, which is the failure mode this
// whole change exists to end.
func TestDirectoryRolesMatchTheWire(t *testing.T) {
	if roleCoordinator != "coordinator" || roleAccount != "account" {
		t.Fatalf("role constants are (%q, %q), want (\"coordinator\", \"account\") — the wire values cmd/coordinator's buildSnapshot writes", roleCoordinator, roleAccount)
	}
	// And the snapshot type finds them by exactly those strings.
	snap := coldstart.Snapshot{Entries: []coldstart.Entry{
		coordinatorEntry("198.51.100.1:8080"),
		accountEntry("https://account.example:8443"),
		{Role: "exit", ID: "e1", Addr: "198.51.100.9:443"},
	}}
	d := Directory{Snapshot: snap, Signed: []byte("signed")}
	if got := d.Coordinators(); !reflect.DeepEqual(got, []string{"198.51.100.1:8080"}) {
		t.Errorf("Coordinators() = %v", got)
	}
	if got := d.AccountServiceURLs(); !reflect.DeepEqual(got, []string{"https://account.example:8443"}) {
		t.Errorf("AccountServiceURLs() = %v", got)
	}
}

// TestAnAccountEntryIsTheShapeAccountclientAccepts is the cross-package check
// that matters more than the role string: the account service is addressed by
// URL and every other role by host:port, so an entry carrying the wrong shape
// would verify, be adopted, and then be refused by the very client it was
// fetched for.
func TestAnAccountEntryIsTheShapeAccountclientAccepts(t *testing.T) {
	d := Directory{
		Snapshot: coldstart.Snapshot{Entries: []coldstart.Entry{accountEntry("https://account.example:8443")}},
		Signed:   []byte("signed"),
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := accountclient.New(accountclient.Config{
		BaseURLs:     d.AccountServiceURLs(),
		Audience:     "account.test",
		ServerCAFile: ca,
	}); err != nil {
		t.Fatalf("accountclient refused the address shape the directory publishes: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Acquisition
// ---------------------------------------------------------------------------

// TestNoInviteLeavesThisClientExactlyAsItWas is the compatibility floor, and it
// is the one row of this file that describes every install in the field: a
// config with no invite does no I/O, holds no directory, and dials precisely
// what it was installed with.
func TestNoInviteLeavesThisClientExactlyAsItWas(t *testing.T) {
	useTempConfigDir(t)
	cfg := Config{
		Coordinators:       []string{"198.51.100.1:8080"},
		AccountServiceURLs: []string{"https://account.example:8443"},
	}
	var logged []string
	dir, err := AcquireDirectory(context.Background(), cfg, Directory{}, func(f string, a ...any) {
		logged = append(logged, f)
	})
	if err != nil {
		t.Fatalf("a client with no invite must not fail: %v", err)
	}
	if dir.Held() {
		t.Fatalf("a client with no invite acquired a directory: %+v", dir)
	}
	if len(logged) != 0 {
		t.Errorf("a client with no invite logged %v — nothing happened and nothing should be said about it", logged)
	}
	coords, urls := effectiveAddrs(cfg, dir)
	if !reflect.DeepEqual(coords, cfg.Coordinators) {
		t.Errorf("coordinators = %v, want the configured %v", coords, cfg.Coordinators)
	}
	if !reflect.DeepEqual(urls, cfg.AccountServiceURLs) {
		t.Errorf("account service = %v, want the configured %v", urls, cfg.AccountServiceURLs)
	}
}

// TestAMalformedInviteIsRefusedRatherThanIgnored: the alternative is the worst
// state available. A user who lost a character off the end of the string would
// have a client that looks configured to follow a moved address, silently does
// not, and says nothing until the day an address moves.
func TestAMalformedInviteIsRefusedRatherThanIgnored(t *testing.T) {
	useTempConfigDir(t)
	for _, in := range []string{"bacchus1:not-base64!!", "bacchus1:", "nonsense", "bacchus1:AAAA"} {
		_, err := AcquireDirectory(context.Background(), Config{Invite: in}, Directory{}, nil)
		if err == nil {
			t.Fatalf("AcquireDirectory(%q) returned no error: a typo in the invite must be refused, named, not silently disable directory updates", in)
		}
		if !strings.Contains(err.Error(), "invite") {
			t.Errorf("error %q does not name the field the user has to fix", err)
		}
	}
	// Whitespace around a good invite is not a typo: an invite arrives by
	// messenger and is pasted.
	d := newTestDirectory(t, coordinatorEntry("198.51.100.1:8080"))
	got, err := AcquireDirectory(context.Background(), Config{Invite: "  " + d.invite + "\n"}, Directory{}, nil)
	if err != nil {
		t.Fatalf("a pasted invite with surrounding whitespace was refused: %v", err)
	}
	if !got.Held() {
		t.Fatal("a pasted invite with surrounding whitespace fetched nothing")
	}
}

// TestAClientFetchesVerifiesAndCachesADirectory is the first done-when, driven
// end to end against a real coldstart server over a real socket.
func TestAClientFetchesVerifiesAndCachesADirectory(t *testing.T) {
	useTempConfigDir(t)
	d := newTestDirectory(t,
		coordinatorEntry("198.51.100.7:8080"),
		accountEntry("https://account.example:8443"),
	)

	dir, err := AcquireDirectory(context.Background(), Config{Invite: d.invite}, Directory{}, t.Logf)
	if err != nil {
		t.Fatalf("AcquireDirectory: %v", err)
	}
	if !dir.Held() {
		t.Fatal("nothing was acquired from a live coordinator")
	}
	if got := dir.Coordinators(); !reflect.DeepEqual(got, []string{"198.51.100.7:8080"}) {
		t.Errorf("Coordinators() = %v", got)
	}
	if got := dir.AccountServiceURLs(); !reflect.DeepEqual(got, []string{"https://account.example:8443"}) {
		t.Errorf("AccountServiceURLs() = %v", got)
	}

	// Cached as the SIGNED wire form, verbatim: anything else could not be
	// re-verified, and re-verification is the only reason to keep it.
	cached, err := coldstart.LoadCache(DefaultDirectoryCachePath())
	if err != nil {
		t.Fatalf("the fetched directory was not cached: %v", err)
	}
	if _, err := coldstart.Verify(d.pub, cached); err != nil {
		t.Fatalf("the cached bytes do not verify: %v", err)
	}
}

// TestACachedDirectoryIsUsedWithoutTheNetwork: the cache is the offline-start
// path, so it has to answer with the coordinator unreachable rather than merely
// faster than it.
func TestACachedDirectoryIsUsedWithoutTheNetwork(t *testing.T) {
	useTempConfigDir(t)
	d := newTestDirectory(t, coordinatorEntry("198.51.100.7:8080"))
	writeCache(t, d.snapshot)

	// A coordinator address nothing answers on. The fetch would fail; the cache
	// must mean it is never attempted.
	inv, err := coldstart.DecodeInvite(d.invite)
	if err != nil {
		t.Fatal(err)
	}
	inv.Coordinator = "127.0.0.1:1"
	dead, err := coldstart.EncodeInvite(inv)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	dir, err := AcquireDirectory(context.Background(), Config{Invite: dead}, Directory{}, t.Logf)
	if err != nil {
		t.Fatalf("AcquireDirectory: %v", err)
	}
	if !dir.Held() {
		t.Fatal("a valid cached directory was not adopted")
	}
	if elapsed := time.Since(start); elapsed > directoryTimeout {
		t.Errorf("took %s: the cache did not short-circuit the fetch", elapsed)
	}
}

// TestARejectedCachedDirectoryFallsBackToTheConfiguredAddresses is the third
// done-when, and it is one test rather than three because the three cases have
// to produce the SAME outcome: an expired snapshot, one signed by a key this
// client does not hold, and one whose bytes are damaged are all "no directory",
// never "no addresses".
//
// The wrong-key row is what makes an invite swap safe. An operator who re-issues
// leaves the previous cache sitting at the path this build reads, and adopting
// it because it happens to be there would keep a client following a directory it
// is no longer entitled to read.
func TestARejectedCachedDirectoryFallsBackToTheConfiguredAddresses(t *testing.T) {
	configured := Config{
		Coordinators:       []string{"198.51.100.1:8080"},
		AccountServiceURLs: []string{"https://configured.example:8443"},
	}

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPub

	cases := []struct {
		name  string
		cache func(t *testing.T, d *testDirectory) []byte
	}{
		{
			name: "expired",
			cache: func(t *testing.T, d *testDirectory) []byte {
				now := time.Now()
				return d.sign(t, coldstart.Snapshot{
					Version:   coldstart.SnapshotVersion,
					IssuedAt:  now.Add(-10 * time.Minute),
					ExpiresAt: now.Add(-5 * time.Minute),
					Entries:   []coldstart.Entry{coordinatorEntry("203.0.113.9:8080")},
				})
			},
		},
		{
			name: "signed by a key this invite does not name",
			cache: func(t *testing.T, d *testDirectory) []byte {
				signed, err := coldstart.Sign(otherPriv, d.freshSnapshot(coordinatorEntry("203.0.113.9:8080")))
				if err != nil {
					t.Fatal(err)
				}
				return signed
			},
		},
		{
			name: "truncated",
			cache: func(t *testing.T, d *testDirectory) []byte {
				return d.snapshot[:len(d.snapshot)/2]
			},
		},
		{
			name:  "not a snapshot at all",
			cache: func(t *testing.T, d *testDirectory) []byte { return []byte("{}") },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useTempConfigDir(t)
			d := newTestDirectory(t, coordinatorEntry("203.0.113.9:8080"))
			writeCache(t, tc.cache(t, d))

			// The coordinator is unreachable too, so the ONLY thing that could
			// produce a directory here is the cache this test says must be
			// refused.
			inv, err := coldstart.DecodeInvite(d.invite)
			if err != nil {
				t.Fatal(err)
			}
			inv.Coordinator = "127.0.0.1:1"
			dead, err := coldstart.EncodeInvite(inv)
			if err != nil {
				t.Fatal(err)
			}

			cfg := configured
			cfg.Invite = dead
			dir, err := AcquireDirectory(context.Background(), cfg, Directory{}, t.Logf)
			if err != nil {
				t.Fatalf("a refused cache must not fail the connect: %v", err)
			}
			if dir.Held() {
				t.Fatalf("a %s snapshot was adopted: %+v", tc.name, dir.Snapshot)
			}
			coords, urls := effectiveAddrs(cfg, dir)
			if !reflect.DeepEqual(coords, configured.Coordinators) {
				t.Errorf("coordinators = %v, want the configured %v — the fallback is the seed, never nothing", coords, configured.Coordinators)
			}
			if !reflect.DeepEqual(urls, configured.AccountServiceURLs) {
				t.Errorf("account service = %v, want the configured %v", urls, configured.AccountServiceURLs)
			}
		})
	}
}

// TestAHeldDirectoryIsReCheckedAgainstTheCurrentInvite: the in-memory tier is an
// optimisation, and an optimisation that outlives the credential it was fetched
// under is a bug. Swapping the invite must take effect at the next connect, not
// when the old snapshot happens to expire.
func TestAHeldDirectoryIsReCheckedAgainstTheCurrentInvite(t *testing.T) {
	useTempConfigDir(t)
	first := newTestDirectory(t, coordinatorEntry("198.51.100.1:8080"))
	second := newTestDirectory(t, coordinatorEntry("203.0.113.2:8080"))

	held, err := AcquireDirectory(context.Background(), Config{Invite: first.invite}, Directory{}, t.Logf)
	if err != nil || !held.Held() {
		t.Fatalf("first acquisition: %v %+v", err, held)
	}

	// The same held directory, now offered against a DIFFERENT operator's
	// invite: it must be discarded and the new coordinator asked instead.
	got, err := AcquireDirectory(context.Background(), Config{Invite: second.invite}, held, t.Logf)
	if err != nil {
		t.Fatalf("second acquisition: %v", err)
	}
	if want := []string{"203.0.113.2:8080"}; !reflect.DeepEqual(got.Coordinators(), want) {
		t.Fatalf("Coordinators() = %v, want %v — the snapshot fetched under the previous invite is still answering", got.Coordinators(), want)
	}

	// And the matching invite short-circuits, which is what makes the tier worth
	// having: the same bytes come back.
	again, err := AcquireDirectory(context.Background(), Config{Invite: second.invite}, got, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.Signed, got.Signed) {
		t.Error("a still-valid held directory was re-fetched rather than reused")
	}
}

// TestAnUnreachableCoordinatorLeavesTheClientOnItsConfiguredAddresses: the
// directory is an improvement on a static config, never a precondition for
// using one.
func TestAnUnreachableCoordinatorLeavesTheClientOnItsConfiguredAddresses(t *testing.T) {
	useTempConfigDir(t)
	d := newTestDirectory(t, coordinatorEntry("203.0.113.9:8080"))
	inv, err := coldstart.DecodeInvite(d.invite)
	if err != nil {
		t.Fatal(err)
	}
	inv.Coordinator = "127.0.0.1:1"
	dead, err := coldstart.EncodeInvite(inv)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{Invite: dead, Coordinators: []string{"198.51.100.1:8080"}}
	var logged []string
	dir, err := AcquireDirectory(context.Background(), cfg, Directory{}, func(f string, a ...any) {
		logged = append(logged, f)
	})
	if err != nil {
		t.Fatalf("an unreachable coordinator must not fail the connect: %v", err)
	}
	if dir.Held() {
		t.Fatal("a directory was produced with nothing answering")
	}
	if len(logged) == 0 {
		t.Error("nothing was logged: a client that silently stopped following the directory is indistinguishable from one that never had an invite")
	}
	coords, _ := effectiveAddrs(cfg, dir)
	if !reflect.DeepEqual(coords, cfg.Coordinators) {
		t.Errorf("coordinators = %v, want the configured %v", coords, cfg.Coordinators)
	}
}

// ---------------------------------------------------------------------------
// Which list wins
// ---------------------------------------------------------------------------

// TestEffectiveCoordinatorsLeadsWithTheDirectoryAndKeepsTheSeed pins the
// asymmetry against EffectiveAccountServiceURLs below, and it is a correction to
// what ADR-0016 decision 4 says read literally.
//
// cmd/coordinator's buildSnapshot puts exactly ONE coordinator entry in a
// snapshot — its own advertised address — because a coordinator has nothing to
// say about its peers. So a directory that REPLACED this list would narrow an
// operator's three-coordinator pool to whichever one signed the snapshot the
// client happened to fetch, which is redundancy deleted by a client-side change
// nobody asked for. What the directory contributes here is precedence.
func TestEffectiveCoordinatorsLeadsWithTheDirectoryAndKeepsTheSeed(t *testing.T) {
	cases := []struct {
		name       string
		directory  []string
		configured []string
		want       []string
	}{
		{"no directory is the configured pool", nil, []string{"a:1", "b:2"}, []string{"a:1", "b:2"}},
		{"a moved coordinator is dialled first", []string{"new:1"}, []string{"old:1"}, []string{"new:1", "old:1"}},
		{"the operator's other coordinators survive", []string{"b:2"}, []string{"a:1", "b:2", "c:3"}, []string{"b:2", "a:1", "c:3"}},
		{"an address named twice is one address", []string{"a:1"}, []string{"a:1"}, []string{"a:1"}},
		{"blanks are not addresses", []string{"", " "}, []string{"a:1", ""}, []string{"a:1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectiveCoordinators(tc.directory, tc.configured); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("EffectiveCoordinators(%v, %v) = %v, want %v", tc.directory, tc.configured, got, tc.want)
			}
		})
	}
}

// TestEffectiveAccountServiceURLsPrefersTheDirectoryWhole is decision 4 taken
// literally, which is right for THIS role: the configured address is precisely
// the one that goes stale, and one repeatable coordinator flag states the whole
// list, so what arrives is a complete answer rather than one member of a set.
//
// The last row is what makes this shippable to a fleet whose coordinators have
// not been given the flag yet.
func TestEffectiveAccountServiceURLsPrefersTheDirectoryWhole(t *testing.T) {
	cases := []struct {
		name       string
		directory  []string
		configured []string
		want       []string
	}{
		{
			"the directory replaces rather than merges",
			[]string{"https://new:8443"},
			[]string{"https://old:8443"},
			[]string{"https://new:8443"},
		},
		{
			"a planned move published centrally reaches every client",
			[]string{"https://new:8443", "https://newer:8443"},
			[]string{"https://old:8443"},
			[]string{"https://new:8443", "https://newer:8443"},
		},
		{
			"a directory naming no account service leaves the seed alone",
			nil,
			[]string{"https://old:8443", "https://spare:8443"},
			[]string{"https://old:8443", "https://spare:8443"},
		},
		{
			"a directory naming only blanks is a directory naming none",
			[]string{"", "  "},
			[]string{"https://old:8443"},
			[]string{"https://old:8443"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectiveAccountServiceURLs(tc.directory, tc.configured); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("EffectiveAccountServiceURLs(%v, %v) = %v, want %v", tc.directory, tc.configured, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The headline: a client follows a moved account service
// ---------------------------------------------------------------------------

// TestAClientRenewsOffTheDirectoryWhenItsConfiguredAddressIsDead is the second
// done-when, and the whole reason bacchus#193 exists.
//
// The setup is the outage ADR-0016 describes: the account service has moved, the
// address in this client's config file answers nothing, and the only place the
// new one exists is a coordinator-signed directory. Nothing about this client's
// configuration is edited — that is the point, because there is nobody to edit
// it on the devices this is for.
//
// It drives Controller.deviceRenewHook, which is the function core calls from
// deviceRenewLoop, so what is exercised is the real seam rather than a
// rehearsal of it.
func TestAClientRenewsOffTheDirectoryWhenItsConfiguredAddressIsDead(t *testing.T) {
	useTempConfigDir(t)
	live := newEnrollmentTestService(t)
	live.renewOK = true

	d := newTestDirectory(t, accountEntry(live.srv.URL))

	cfg := Config{
		Coordinators: []string{"127.0.0.1:1"},
		Invite:       d.invite,
		// The address the service USED to be at. Port 1 on loopback refuses
		// immediately, so a client that used it fails fast and visibly rather
		// than by timing out.
		AccountServiceURLs:     []string{"https://127.0.0.1:1"},
		AccountServiceAudience: "account.test",
		AccountServiceCA:       live.ca,
		DeviceCredDir:          t.TempDir(),
	}
	ctrl := newProxyOnlyController(cfg)
	ctrl.Logf = t.Logf

	dir, err := ctrl.acquireDirectory(context.Background())
	if err != nil {
		t.Fatalf("acquireDirectory: %v", err)
	}
	if !dir.Held() {
		t.Fatal("no directory was acquired, so this test would prove nothing")
	}
	_, accountURLs := effectiveAddrs(ctrl.cfg, dir)
	if !reflect.DeepEqual(accountURLs, []string{strings.TrimRight(live.srv.URL, "/")}) {
		t.Fatalf("account service addresses = %v, want the live one the directory names (%s)", accountURLs, live.srv.URL)
	}

	dc, err := ctrl.openDeviceCredential(accountURLs)
	if err != nil {
		t.Fatalf("openDeviceCredential: %v", err)
	}
	if dc.client == nil {
		t.Fatal("no account client was built for a config that names an account service")
	}

	fresh, err := ctrl.deviceRenewHook(dc)(context.Background(), testRenewRequest(t))
	if err != nil {
		t.Fatalf("renewal against the address the directory names failed: %v", err)
	}
	if !fresh.Presentable() {
		t.Fatalf("renewal returned an unusable credential: %+v", fresh)
	}
	if st := ctrl.CredentialState(); st.RenewalFailing {
		t.Error("the controller recorded a renewal failure for a renewal that worked")
	}
}

// TestWithoutTheDirectoryTheSameClientCannotRenew is the control for the test
// above. Without it, that one proves that a client with a working address can
// reach a working service — which was never in doubt — rather than that the
// directory is what supplied it.
func TestWithoutTheDirectoryTheSameClientCannotRenew(t *testing.T) {
	useTempConfigDir(t)
	live := newEnrollmentTestService(t)
	live.renewOK = true

	cfg := Config{
		Coordinators:           []string{"127.0.0.1:1"},
		AccountServiceURLs:     []string{"https://127.0.0.1:1"},
		AccountServiceAudience: "account.test",
		AccountServiceCA:       live.ca,
		DeviceCredDir:          t.TempDir(),
	}
	ctrl := newProxyOnlyController(cfg)
	ctrl.Logf = t.Logf

	dc, err := ctrl.openDeviceCredential(cfg.AccountServiceAddresses())
	if err != nil {
		t.Fatalf("openDeviceCredential: %v", err)
	}
	if _, err := ctrl.deviceRenewHook(dc)(context.Background(), testRenewRequest(t)); err == nil {
		t.Fatal("renewal against the dead configured address succeeded, so this pair of tests measures nothing")
	}
	if st := ctrl.CredentialState(); !st.RenewalFailing {
		t.Error("a failed renewal was not recorded as one")
	}
}

// testRenewRequest is what core hands Config.DeviceRenew. The signature is over
// a fresh key and the test service does not check it — core/accountclient's own
// tests are where the assertion is exercised, against bytes the real service
// produced.
func testRenewRequest(t *testing.T) core.DeviceRenewRequest {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return core.DeviceRenewRequest{
		DevicePub: pub,
		Current:   devicestore.Credential{Device: "bacchusd1:" + testCredEnvelopeBody, IssuerCert: "bacchusi1:issuer"},
		Sign: func(audience string, challenge []byte) ([]byte, error) {
			return ed25519.Sign(priv, append([]byte(audience), challenge...)), nil
		},
	}
}

// ---------------------------------------------------------------------------
// The template
// ---------------------------------------------------------------------------

// TestTheTemplateShipsNoInvite is ADR-0061's first constraint, as a test.
//
// An invite carries a bootstrap secret, and coldstart.LoadMemStore's own doc
// records that every entry in a coordinator's secrets file is trusted equally —
// so a populated invite in the file every install copies is a working credential
// for the whole network, held by anyone who downloads the artifact. The key is
// present and EMPTY, which is a slot rather than a credential, and that is what
// this asserts in both directions.
func TestTheTemplateShipsNoInvite(t *testing.T) {
	b, err := os.ReadFile("../../bacchus-fyne.config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	v, ok := raw["invite"]
	if !ok {
		t.Fatal("the template has no \"invite\" key, so nobody copying it can discover the field")
	}
	var got string
	if err := json.Unmarshal(v, &got); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != "" {
		t.Fatalf("the template ships an invite (%q). It is per-recipient and carries a bootstrap secret: shipping one in a downloadable artifact hands that secret to everyone who downloads it, which is exactly the censor this project is built against", got)
	}
}

// testCAPEM is a throwaway self-signed certificate in PEM form, for the one
// check that needs a CA file to exist and nothing to be verified against it.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	s := newEnrollmentTestService(t)
	b, err := os.ReadFile(s.ca)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// errNoInviteIsNotAFailure documents the one sentinel this file leans on, so a
// refactor that makes it a real error surfaces here.
var _ = errors.Is(errNoInvite, errNoInvite)
