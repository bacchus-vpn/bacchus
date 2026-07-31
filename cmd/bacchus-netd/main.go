//go:build linux

// Command bacchus-netd is the privileged half of Linux device-wide enforcement:
// a root helper that owns the thirteen `osNet` operations needing
// CAP_NET_ADMIN, reached over a peer-credential-gated unix socket. ADR-0049 is
// the decision record; this is its implementation.
//
// Nothing here decides policy. clients/fyne runs as the desktop user with no
// capabilities and keeps every decision it already had — what to protect, in
// which split-tunnel mode, whether to arm the kill-switch, and in what order to
// bring the tunnel up. This process executes primitives and validates that it
// was asked for one it is willing to perform.
//
// # What a compromised client can and cannot make this do
//
// ADR-0049 §9 states the boundary's limits, and they are worth repeating where
// the code is. A client that has been fully compromised can issue every request
// in the protocol, because that is what the protocol is for: it can decline to
// arm the kill-switch, lift one, add an exclusion route broad enough to carry
// most traffic out the physical interface, or re-enable IPv6 mid-session. **A
// compromised GUI can turn the VPN off.** It cannot be otherwise — the GUI is
// the component that decides what to protect.
//
// What it cannot do is what this boundary buys: run code as root, read or write
// files as root, load modules, change any sysctl but disable_ipv6 on the one
// physical interface this helper derived itself, touch routing state outside
// this helper's own table, reach another user's session, or run two conflicting
// enforcement states at once. So compromise of the GUI costs the user their VPN
// protection, not their machine.
//
// # The dependency decision
//
// Both halves of the kernel conversation are hand-rolled against
// golang.org/x/sys/unix, which is already a direct dependency. The alternative
// — vishvananda/netlink for routes and google/nftables for the firewall — is
// much less code and two new modules, and it is a genuinely defensible answer.
// This is the argument for the one taken, since it is the more expensive one to
// write:
//
//   - The trust context is not ordinary. Every dependency in this binary is
//     code running as root, reachable from an unprivileged local process. That
//     is a different calculus from gvisor or fyne, which run as the user; a
//     module here is a permanent upgrade obligation on a root attack surface.
//     Taking both libraries adds them plus mdlayher/netlink, mdlayher/socket,
//     josharian/native and vishvananda/netns transitively.
//   - What is actually needed is small, fixed and stable. Not a general
//     rtnetlink client: four message types, one dump, and a fib rule. Not a
//     general nftables client: one table, one chain, one set and five rules,
//     whose shape is fixed by ADR-0014's policy and does not vary at runtime.
//     Hand-rolling a fixed message set is a different proposition from
//     hand-rolling a library.
//   - The usual argument against hand-rolling — that you cannot be sure the
//     encoding is right — does not hold here, and that is what tipped it. The
//     netns harness gives this lane a real kernel in CI, so every message is
//     asserted against the kernel's own answer rather than against a
//     recording. That is not a hypothetical: writing it this way surfaced a
//     required attribute the kernel rejects the set without, two meta keys that
//     encode to a VALID comparison against the wrong field (so the transaction
//     succeeds and the rule silently matches nothing), an rt_protocol id that
//     collided with RTPROT_BGP, and a buffer-aliasing bug that corrupted any
//     netlink dump spanning more than one datagram. A library would have
//     avoided the first three; the fourth was mine either way, and only the
//     kernel tests would have caught it.
//
// The honest cost, recorded because ADR-0049 §4 asked for it to be: this is
// more code than the alternative, and the nftables expression encoding is the
// intricate part it warned about.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// defaultSocket is ADR-0049 §1's address. deploy/bacchus-netd.socket
	// creates it with mode 0660 and group bacchus.
	defaultSocket = "/run/bacchus/netd.sock"

	// socketMode is what the socket is chmod'd to when this process creates it
	// itself (no systemd activation). Group-writable, world-nothing.
	socketMode = 0o660
)

func main() {
	socketPath := flag.String("socket", defaultSocket, "unix socket to listen on")
	group := flag.String("group", "bacchus", "group that may connect (when this process creates the socket itself)")
	allowNoLogin := flag.Bool("allow-without-logind", false,
		"accept a peer whose logind session cannot be checked. For hosts without systemd-logind, "+
			"where session ownership cannot be established; the socket's group permission becomes the only gate.")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags)
	logf := func(format string, args ...any) { logger.Printf(format, args...) }

	if os.Geteuid() != 0 && !hasNetAdmin() {
		logger.Fatalf("bacchus-netd needs CAP_NET_ADMIN (run it as root, or give the unit AmbientCapabilities=CAP_NET_ADMIN)")
	}

	ln, err := listen(*socketPath, *group)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	h := newHelper(logf, *allowNoLogin)

	// A lockdown left behind by a crashed session is lifted when a client next
	// opens a session, not here. Doing it at startup would be wrong under
	// socket activation: the helper starts BECAUSE a client connected, so
	// "startup" and "a client is asking" are the same moment, and a helper
	// restarted for any other reason would lift a lockdown that is still
	// deliberately in force.

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		// Deliberately does NOT lift the kill-switch. It is nftables state and
		// lives in the kernel, so an idle or restarting helper leaves the
		// machine protected; a helper that unlocked on the way out would break
		// the one guarantee parity item 2 asks for (ADR-0049 §8).
		logf("shutting down; any armed lockdown stays in force")
		ln.Close()
	}()

	logf("bacchus-netd listening on %s", *socketPath)
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return // listener closed
		}
		// One goroutine per connection, even though only one SESSION may exist
		// at a time. The two are not the same thing, and conflating them is a
		// bug: a client holds its connection for the whole life of a session,
		// so serving serially would leave a second client blocked in connect()
		// with no answer instead of refused. ADR-0049 §3.2 requires the second
		// client to get EBUSY, which is an answer it can only receive if its
		// connection is accepted and read. The one-session rule is enforced
		// where the session actually lives, in handleOpen under h.mu.
		go h.serve(conn)
	}
}

// listen returns the socket to serve on, preferring one systemd already
// created.
func listen(path, group string) (*net.UnixListener, error) {
	if ln, ok, err := systemdListener(); ok {
		return ln, err
	}
	return listenOwn(path, group)
}

// systemdListener adopts a socket passed by systemd socket activation.
//
// Socket activation is an optimization rather than a requirement (ADR-0049's
// Consequences): the helper is a plain binary listening on a unix socket and
// any supervisor can start it. What it buys is that the socket exists with the
// right owner and mode from boot, so a client's connect starts the helper
// rather than failing because nothing is running yet.
func systemdListener() (*net.UnixListener, bool, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, false, nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		return nil, false, nil
	}
	// SD_LISTEN_FDS_START.
	const fd = 3
	unix.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "systemd-socket")
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return nil, true, fmt.Errorf("adopt the systemd socket: %w", err)
	}
	unixLn, ok := ln.(*net.UnixListener)
	if !ok {
		return nil, true, fmt.Errorf("systemd passed a %T, not a unix socket", ln)
	}
	return unixLn, true, nil
}

// listenOwn creates the socket directly, for a host with no socket activation.
func listenOwn(path, group string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// A stale socket from an unclean exit would make Listen fail with EADDRINUSE
	// forever. Removing it is safe: we hold no lock on it, and a live helper
	// would already have failed the CAP_NET_ADMIN check or be the one process
	// systemd allows.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}

	// Mode before group: between Listen and Chown the socket exists, and it
	// must never be reachable by more than its final audience in that window.
	if err := os.Chmod(path, socketMode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	gid, err := lookupGroup(group)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("group %q: %w (create it, or pass -group)", group, err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chown %s to group %s: %w", path, group, err)
	}
	return ln, nil
}

// lookupGroup resolves a group name to a gid without cgo. os/user's pure-Go
// path reads /etc/group, which is what a packaged install uses.
func lookupGroup(name string) (int, error) {
	g, err := userLookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g)
}

// hasNetAdmin reports whether this process holds CAP_NET_ADMIN in its effective
// set, so a unit using AmbientCapabilities rather than User=root still starts.
func hasNetAdmin() bool {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: int32(os.Getpid())}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	const capNetAdmin = 12 // CAP_NET_ADMIN
	return data[0].Effective&(1<<capNetAdmin) != 0
}

// userLookupGroup is os/user.LookupGroup, wrapped so the one cgo-sensitive
// call in this binary is in a single place. The pure-Go implementation reads
// /etc/group, which is what a packaged install has.
func userLookupGroup(name string) (string, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return "", err
	}
	return g.Gid, nil
}
