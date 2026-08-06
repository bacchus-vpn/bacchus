//go:build windows

// OS-level network configuration for full-device routing on Windows: reading
// the current default route, excluding the coordinator/STUN/TURN endpoints
// from the tunnel (so the WebRTC session itself doesn't loop into the TUN
// device), installing the tunnel's split-default route, blocking IPv6 on the
// physical adapter, and (split-tunnel "include" mode only, issue #64) routing
// specific destinations *into* the tunnel adapter instead of the split-default
// capturing everything.
//
// Everything here shells out to PowerShell's NetTCPIP cmdlets rather than
// calling IP Helper API directly — structured, well-documented, and avoids
// hand-parsing `route print`/`netsh` text output. All of it requires the
// process to be running elevated (Administrator); see README.
//
// This is one half of the Windows osNet implementation (killswitch_windows.go
// is the other) — the 414-line "Total" row of ADR-0039's file-by-file costing,
// minus the address handling and log redaction that turned out to be portable
// and now live in addrs.go / redact.go. What remains is genuinely
// Windows-only: every function below is a cmdlet invocation, and both the
// cmdlets and syscall.SysProcAttr's CreationFlags field exist on no other
// platform.
package enforcement

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

const tunAdapterName = "Bacchus"

// createNoWindow is the CREATE_NO_WINDOW process-creation flag. The client is
// built -H=windowsgui and has no console of its own, so without this flag every
// child powershell.exe allocates and flashes its own console window. runPS
// fires constantly — route installs, gateway refreshes, kill-switch and
// per-domain split-tunnel updates — so the effect is a storm of console
// windows, not a one-off. CombinedOutput still captures the child's output via
// pipes; only the window is suppressed.
const createNoWindow = 0x08000000

// winOS is the Windows osNet implementation: PowerShell invocations, plus the
// two things every one of them needs.
//
// logf is the client's log sink, injected via Policy.Logf rather than called
// by name — the client owns its sink and is not importable from here. This
// package had two callers with two sinks until bacchus#138 retired one.
//
// run is the PowerShell escape hatch, and it is the reason the ordering
// guarantees in this file are testable at all. In production it is nil and
// runPS shells out for real; a test sets it to record the exact script
// sequence, which is how parity item 5's "excluded before the dial, never
// orphaned" and item 2's arm/unwind ordering get asserted without an elevated
// Windows host and a live route table. Same idea as poolExcluder's injected
// excludeFn/allowFn, one layer down.
type winOS struct {
	logf func(string, ...any)
	run  func(script string) (string, error)
}

func (o *winOS) log(format string, args ...any) {
	if o.logf != nil {
		o.logf(format, args...)
	}
}

// newPSCmd builds the powershell.exe invocation every OS-config call in this
// file runs, windowless (see createNoWindow).
func newPSCmd(script string) *exec.Cmd {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	return cmd
}

func (o *winOS) runPS(script string) (string, error) {
	if o.run != nil {
		return o.run(script)
	}
	out, err := newPSCmd(script).CombinedOutput()
	if err != nil {
		// These OS-config calls aren't core.Events, so a failure otherwise leaves no
		// trace in the log — only a truncated tray status. Record the failing
		// command's first line plus PowerShell's actual message; the IPv6-loopback
		// firewall rejection that fail-closed the tunnel was invisible without this.
		//
		// Both are cut to their first line and redacted before logging (issue
		// #140): New-NetRoute and New-NetFirewallRule calls carry the
		// coordinator/exit/relay addresses as literal arguments, and
		// PowerShell's own multi-line error rendering re-echoes the failing
		// source line a second time as part of its "At line:N char:M" position
		// block — a redaction-bypassing copy, since it's PowerShell's own
		// reconstruction rather than anything that flows through redactIPs
		// upstream, and console-width truncation there can hand back a bare
		// fragment of an address (e.g. "203.0.113" with the last octet cut).
		// That block is in the target OS's display language, not necessarily
		// English, so pattern-matching its wording to strip just that part
		// isn't reliable either — first line only sidesteps it entirely. The
		// error message itself (the actual diagnostic value) is always that
		// first line; everything past it is position/category detail this
		// client has never needed to log. bacchus.log is a disk file a user
		// may hand over for support — naming infra addresses on it is a
		// forensic footprint for a client whose whole point is running in a
		// hostile jurisdiction.
		//
		// That file was real, then was not, and is again. It belonged to the
		// Windows tray client retired in bacchus#138, after which nothing wrote
		// it and this reasoning was protecting a sink that did not exist
		// (bacchus#187). clients/fyne keeps one now — at
		// %APPDATA%\Bacchus\bacchus.log and the XDG equivalent — and applies
		// RedactAddresses to EVERY line reaching it, whoever wrote it, so what
		// happens here is the first of two passes rather than the only one. It
		// stays first because the truncation above is not redaction and no sink
		// could do it: only this call site knows that PowerShell's position
		// block is a re-echo of the script rather than diagnostic text.
		//
		// The returned error below is still deliberately left full and
		// unredacted, and that exemption was RE-CHECKED rather than carried
		// over. It reaches exactly one place: Controller.abort wraps it into a
		// Detail, which OnDetail puts on the main window's detail line. Nothing
		// on that path writes it to the log. So it is the same ephemeral,
		// in-session surface the retired client's tray status was, and it keeps
		// full diagnostic value for the running session.
		first := redactIPs(firstLine(strings.TrimSpace(script)))
		outFirst := redactIPs(firstLine(strings.TrimSpace(string(out))))
		o.log("[tun] ps failed: %s | %s", first, outFirst)
		return "", fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// defaultGateway returns the current best (lowest-metric) IPv4 default
// route: its next hop, and the physical interface carrying it. It also
// best-effort resolves that same interface's IPv6 default route, if any
// (issue #117, gatewayInfo.nextHopV6) — a missing/absent IPv6 route is not an
// error, since most networks and most of the tunnel's lifetime have none
// (disablePhysicalIPv6); only the IPv4 lookup is required to succeed.
func (o *winOS) defaultGateway() (gatewayInfo, error) {
	out, err := o.runPS(`$r = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
		Sort-Object -Property RouteMetric | Select-Object -First 1
	$r6 = Get-NetRoute -DestinationPrefix "::/0" -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue |
		Sort-Object -Property RouteMetric | Select-Object -First 1
	"$($r.NextHop)|$($r.InterfaceIndex)|$($r.InterfaceAlias)|$($r6.NextHop)"`)
	if err != nil {
		return gatewayInfo{}, err
	}
	parts := strings.SplitN(out, "|", 4)
	if len(parts) != 4 {
		return gatewayInfo{}, fmt.Errorf("unexpected Get-NetRoute output: %q", out)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return gatewayInfo{}, fmt.Errorf("bad interface index %q: %v", parts[1], err)
	}
	return gatewayInfo{
		nextHop:   strings.TrimSpace(parts[0]),
		ifIndex:   idx,
		ifAlias:   strings.TrimSpace(parts[2]),
		nextHopV6: strings.TrimSpace(parts[3]),
	}, nil
}

// addExclusionRoutes routes each prefix via the real default gateway
// (bypassing the tunnel's split-default override) so traffic to it keeps
// flowing over the physical interface instead of looping into the TUN
// device. prefixes may be bare IPs (normalized to a /32 host route) or full
// CIDRs — the control-plane endpoints resolve to bare IPs, while
// destination-based split tunnelling (splittunnel.go) also has whole bypass
// CIDRs to exclude. Used unconditionally for the control-plane endpoints, and
// for the bypass/include set specifically in split-tunnel "exclude" mode.
func (o *winOS) addExclusionRoutes(prefixes []string, gw gatewayInfo) {
	for _, p := range prefixes {
		_, _ = o.runPS(fmt.Sprintf(
			`New-NetRoute -DestinationPrefix "%s" -NextHop "%s" -InterfaceIndex %d -RouteMetric 1 -ErrorAction Stop | Out-Null`,
			ensureCIDR(p), gw.nextHop, gw.ifIndex))
	}
}

// addExclusionRoutesV6 is addExclusionRoutes' IPv6 counterpart (issue #117),
// used by poolExcluder for an IPv6 reality exit address. A no-op when gw has
// no IPv6 default route (nextHopV6 == "") — there is then nothing to route an
// exclusion via, which is safe: physical IPv6 is disabled while the tunnel is
// up regardless (disablePhysicalIPv6), so an unexcluded IPv6 dial fails
// closed rather than leaking.
func (o *winOS) addExclusionRoutesV6(prefixes []string, gw gatewayInfo) {
	if gw.nextHopV6 == "" {
		return
	}
	for _, p := range prefixes {
		_, _ = o.runPS(fmt.Sprintf(
			`New-NetRoute -DestinationPrefix "%s" -NextHop "%s" -InterfaceIndex %d -RouteMetric 1 -ErrorAction Stop | Out-Null`,
			ensureCIDR(p), gw.nextHopV6, gw.ifIndex))
	}
}

// addInclusionRoutes is addExclusionRoutes' mirror for split-tunnel "include"
// mode (issue #64): instead of carving a destination *out* of the tunnel's
// split-default route, it routes the destination *into* the tunnel adapter —
// needed because include mode never installs a split-default in the first
// place (see addSplitDefaultRoute), so without this, the bypass/include set
// itself would never be captured by the netstack at all and would just
// follow the untouched physical default straight past the tunnel. Requires
// the tun adapter to already exist (New-NetIPAddress/CreateTUN), unlike
// addExclusionRoutes which only needs the physical gateway.
func (o *winOS) addInclusionRoutes(prefixes []string, tunNextHop string) {
	for _, p := range prefixes {
		_, _ = o.runPS(fmt.Sprintf(
			`New-NetRoute -InterfaceAlias "%s" -DestinationPrefix "%s" -NextHop "%s" -RouteMetric 1 -ErrorAction Stop | Out-Null`,
			tunAdapterName, ensureCIDR(p), tunNextHop))
	}
}

// removeRoutes deletes each prefix's route, regardless of which direction
// added it (addExclusionRoutes' gateway/physical-interface routes and
// addInclusionRoutes' tun-adapter routes are both plain destination-prefix
// entries to Remove-NetRoute — it has no notion of "which side installed
// this"). In practice tun-bound routes are usually already gone by the time
// this runs: standard Windows adapter-deletion semantics remove every route
// bound to an interface when that interface disappears, so tunnel.go's
// teardown order (dev.Close() before this, in Close()) should already have
// cleared them — this is expected to be a no-op for those and to only do
// real work for the gateway-bound ones. This isn't a new assumption
// specific to include mode: exclude mode's split-default route has always
// been tun-adapter-bound with no explicit removal call of its own either, so
// it has depended on the exact same Windows behavior ever since ADR-0025
// first shipped — addInclusionRoutes' routes are cleaned up by the identical
// mechanism, not a new or less-tested one. Still, it's asserted here from
// documented Windows routing behavior, not verified against a live wintun
// adapter in this change; if a stale tun-bound route is ever observed
// surviving teardown, this is the first assumption to re-check.
//
// -DestinationPrefix alone also means this matches (and deletes) *any* route
// to that prefix, not just the one this package added — a route the user or
// another program independently created to the same destination would be
// removed too. Pre-existing behavior (unchanged by the rename here), not
// specific to include mode.
func (o *winOS) removeRoutes(prefixes []string) {
	for _, p := range prefixes {
		_, _ = o.runPS(fmt.Sprintf(
			`Remove-NetRoute -DestinationPrefix "%s" -Confirm:$false -ErrorAction SilentlyContinue`, ensureCIDR(p)))
	}
}

// createTUN brings up the wintun adapter. Parity item 7 turns on this failing
// loudly: a client that cannot create the device must say so, not degrade
// silently to an unprotected proxy. That makes this error text the entire
// diagnosis a user gets, and bacchus#135 found both halves of it wrong —
// it named `bacchus.exe`, the tray client retired in bacchus#138, and it named
// elevation as the cause when a missing wintun.dll produces the identical
// failure (confirmed on hardware, bacchus#115). Both halves are answered by
// createTUNAdvice.
func (o *winOS) createTUN() (tun.Device, error) {
	dev, err := tun.CreateTUN(tunAdapterName, 0)
	if err != nil {
		return nil, fmt.Errorf("create wintun adapter — %s: %w", createTUNAdvice(err, runningExeName()), err)
	}
	return dev, nil
}

// defaultExeName is what the advice below calls this program when the OS will
// not say what it is actually called. It is the name the release bundle ships
// (bacchus#136), so it is right for every user who did not rename it.
const defaultExeName = "bacchus-fyne.exe"

// runningExeName is the file name of the running binary, for advice a user has
// to act on by finding that file and right-clicking it.
//
// Read from the process rather than hardcoded, which is the durable half of
// bacchus#135's second finding. The string this replaces named `bacchus.exe`,
// correctly, for as long as clients/windows was the only caller; bacchus#59
// made the text shared and bacchus#138 deleted the binary it named, and at no
// point did anything fail — the advice simply started pointing at a file that
// is not on any user's disk. A name taken from os.Executable cannot go stale
// that way, and it is also literally the file the user launched, which is what
// they have to find again.
func runningExeName() string {
	exe, err := os.Executable()
	if err != nil {
		return defaultExeName
	}
	base := filepath.Base(exe)
	// filepath.Base never returns "", but it does return "." for an empty
	// input and a separator for a path that is all separators. Neither is a
	// file name a user could act on.
	if base == "." || base == string(filepath.Separator) {
		return defaultExeName
	}
	return base
}

// createTUNAdvice turns a tun.CreateTUN failure into the one sentence a user
// can act on, naming which of the two causes actually happened where the error
// says so and both where it does not.
//
// The two are distinguishable because golang.zx2c4.com/wintun wraps its whole
// chain with %w and they enter that chain at different points:
//
//   - No usable wintun.dll. CreateAdapter calls procWintunCreateAdapter.Find()
//     BEFORE any syscall, and Find() calls LoadLibraryEx with
//     LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32 — so
//     "next to the exe" and System32 are the only two places it ever looks,
//     and nothing else on the machine can satisfy it.
//   - No elevation. The DLL loads, the syscall runs, and the driver
//     installation it performs is what fails.
//
// The DLL half is identified POSITIVELY, and the codes in isDLLLoadFailure are
// chosen so that it is: every one of them can only be produced by loading a
// module or resolving an export, so none of them can also be something the
// loaded wintun did. That is why ERROR_FILE_NOT_FOUND is deliberately not
// among them even though "the file is not there" sounds like exactly this
// case — LoadLibraryEx reports a module it cannot find on the search path as
// ERROR_MOD_NOT_FOUND, so a bare 2 here would be coming from somewhere else,
// and claiming a missing DLL over a driver-install failure would send the user
// to re-download a file they already have.
//
// The elevation half is NOT positively identified: ERROR_ACCESS_DENIED is what
// an unelevated run has been observed to produce, but wintun's refusal path is
// not contractual and nothing here should pretend otherwise. So anything
// unrecognised falls through to naming BOTH causes rather than guessing. That
// default is the state bacchus#135 describes — and it is still an improvement
// on it, because the old text named exactly one of the two and was silently
// wrong half the time.
func createTUNAdvice(err error, exe string) string {
	switch {
	case isDLLLoadFailure(err):
		return "wintun.dll is missing or could not be loaded. Put the wintun.dll for this machine's architecture next to " + exe
	case isAccessDenied(err):
		return "run " + exe + " as Administrator"
	default:
		return "check that wintun.dll is next to " + exe + " and that " + exe + " is running as Administrator"
	}
}

// isDLLLoadFailure reports whether err is wintun.dll failing to load or to
// yield its entry points, as opposed to anything the loaded DLL then did.
// Every code here is exclusive to the loader; see createTUNAdvice for why that
// exclusivity is the whole point and which plausible-looking code is left out
// because it does not have it.
func isDLLLoadFailure(err error) bool {
	return errorIsAny(err,
		// The DLL is on neither of the two paths LoadLibraryEx searches.
		windows.ERROR_MOD_NOT_FOUND,
		// A wintun.dll of the wrong architecture — the easiest mistake to
		// make, because the wintun.net zip carries one directory per arch and
		// every one of them holds a file of this same name.
		windows.ERROR_BAD_EXE_FORMAT,
		// It loaded but has no such export: some other wintun.dll, or a
		// version predating the entry point.
		windows.ERROR_PROC_NOT_FOUND,
		// It loaded and its DllMain refused.
		windows.ERROR_DLL_INIT_FAILED,
	)
}

// isAccessDenied reports whether err is the process being told it may not do
// this, which for this call means it is not elevated.
func isAccessDenied(err error) bool {
	return errorIsAny(err, windows.ERROR_ACCESS_DENIED, windows.ERROR_PRIVILEGE_NOT_HELD)
}

// errorIsAny is errors.Is against a set. syscall.Errno is comparable, so
// errors.Is matches it by value at every level of the %w chain above.
func errorIsAny(err error, targets ...syscall.Errno) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

// configureTunInterface assigns addr/prefixLen to the tunnel adapter.
func (o *winOS) configureTunInterface(addr string, prefixLen int) error {
	if _, err := o.runPS(fmt.Sprintf(
		`New-NetIPAddress -InterfaceAlias "%s" -IPAddress "%s" -PrefixLength %d -ErrorAction Stop | Out-Null`,
		tunAdapterName, addr, prefixLen)); err != nil {
		return fmt.Errorf("assign tunnel address: %w", err)
	}
	return nil
}

// addSplitDefaultRoute installs 0.0.0.0/1 + 128.0.0.0/1 via addr (treated as
// on-link) — the standard OpenVPN/WireGuard approach on Windows for
// overriding the real default route without removing it. Split-tunnel
// "exclude" mode (the default) needs this: it captures everything into the
// tunnel and relies on addExclusionRoutes to carve out the bypass set.
// "include" mode must NOT call this (issue #64) — it wants the opposite,
// capturing *nothing* by default and pulling only the bypass/include set in
// via addInclusionRoutes instead, so the real default route stays authoritative
// for everything else. Calling this in include mode is exactly the bug #64
// fixed: it would recapture every "direct" dial straight back into the tunnel.
func (o *winOS) addSplitDefaultRoute(addr string) error {
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if _, err := o.runPS(fmt.Sprintf(
			`New-NetRoute -InterfaceAlias "%s" -DestinationPrefix "%s" -NextHop "%s" -ErrorAction Stop | Out-Null`,
			tunAdapterName, prefix, addr)); err != nil {
			return fmt.Errorf("add split-default route %s: %w", prefix, err)
		}
	}
	return nil
}

// disablePhysicalIPv6 turns off the IPv6 binding on the given physical
// adapter so nothing can leak out over IPv6 while the tunnel (IPv4-only in
// this pass) is up.
func (o *winOS) disablePhysicalIPv6(ifAlias string) {
	_, _ = o.runPS(fmt.Sprintf(
		`Disable-NetAdapterBinding -InterfaceAlias "%s" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue`, ifAlias))
}

func (o *winOS) enablePhysicalIPv6(ifAlias string) {
	_, _ = o.runPS(fmt.Sprintf(
		`Enable-NetAdapterBinding -InterfaceAlias "%s" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue`, ifAlias))
}

// captureDNS does nothing on Windows, and the nothing is the answer rather
// than a gap waiting to be filled.
//
// A Windows resolver's servers are ordinary routable addresses — whatever DHCP
// or the adapter's static configuration supplied. A query to one of them is an
// ordinary packet to an ordinary destination, so it meets the split-default
// route addSplitDefaultRoute installed, enters the TUN, and is intercepted
// portably by tun2socks.go's handleDNSUDP along with everything else. There is
// no local stub listener in the path and nothing on loopback to capture.
//
// This is exactly why bacchus#104 exists as a Linux card. systemd-resolved puts
// a stub on 127.0.0.53, and the kernel consults the `local` table before any
// route, so no split-default can reach it; that platform needs a mechanism
// (ADR-0051) and this one does not. Adding a Windows implementation "for
// symmetry" would mean reconfiguring a resolver that is already pointed
// somewhere the tunnel sees, which can only make it worse.
//
// Windows does have its own DNS-capture question, and it is a different one:
// DNS-over-HTTPS configured in the OS or in a browser bypasses UDP/53 on every
// platform, and neither this method nor the interceptor addresses it. That is
// out of scope here for the same reason it is on Linux — see ADR-0051's
// "What this does not capture".
func (o *winOS) captureDNS() error { return nil }

func (o *winOS) releaseDNS() {}

// errServedEgressUnsupported is the honest refusal, and the thing it protects
// is a disclosure rather than a tunnel. See allowServedEgress below.
var errServedEgressUnsupported = errors.New(
	"carving a volunteered relay or exit's egress out of the tunnel is not implemented on Windows yet (see bacchus#109)")

// allowServedEgress is not implemented on Windows, and this is a refusal rather
// than a stub because the mechanism the Linux side uses does not transfer.
//
// Linux carves the traffic out with a source address the served sockets bind
// plus a fib rule that sends that source to the `main` table (ADR-0053 §2). The
// socket half of that works anywhere — binding a local address needs no
// privilege on either platform. The routing half does not exist here: Windows
// selects a route by longest-match on the DESTINATION and then by metric, and
// its route table has no source selector and no policy-rule layer to add one
// to. So a Windows socket bound to the physical adapter's address still meets
// the `0.0.0.0/1` and `128.0.0.0/1` routes addSplitDefaultRoute installed on the
// tunnel adapter, and still goes into the tunnel. Binding the source changes
// which address the packet claims, not which adapter it leaves by — which is
// the worst of the available outcomes, because it looks like it worked.
//
// The lever that would work is a different one: IP_UNICAST_IF, which pins a
// socket's outgoing interface directly and needs no privilege. That is a real
// route to a Windows implementation, and it is deliberately not taken here for
// two reasons. It is a second, differently-shaped hook in core — an interface
// index, not a local address — so it is not a matter of passing the same value
// to a different call. And bacchus#109's bar is traffic-level: served traffic
// OBSERVED leaving the physical adapter under this machine's own address while
// the user's own traffic is still in the tunnel. The Windows CI job builds and
// smoke-runs this client but cannot arm a kill-switch, create a TUN or route a
// packet, so nothing here could establish that. bacchus#88 is the precedent for
// what a Windows enforcement claim costs: a hardware run.
//
// Until then the refusal in clients/fyne stands on Windows and this returns an
// error, which fails the connect for a serving policy rather than letting one
// through under a claim that would be false. An empty string and a nil error
// would be the one genuinely dangerous answer.
func (o *winOS) allowServedEgress() (string, error) { return "", errServedEgressUnsupported }

func (o *winOS) revokeServedEgress() {}
