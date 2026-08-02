//go:build linux

package appstate

// DNSCaptureIsComplete reports whether this platform captures EVERY DNS query
// a connected device makes. False means the settings window must say so next to
// the DNS field rather than let its "these change what leaves it" notice cover
// a field it does not fully cover.
//
// Linux answers true, and did not always. The gap was real and is now closed by
// bacchus#104 / ADR-0051, so this file agrees with dnscapture_other.go — but it
// stays a separate file rather than being deleted into the default, because
// Linux reaches the same answer by a different route and the difference is what
// a reader here needs.
//
// Everywhere else, true is free: a resolver's configured servers are ordinary
// routable addresses, so its queries meet the split-default route, enter the
// TUN, and are intercepted portably by tun2socks.go's handleDNSUDP. On a
// systemd-resolved machine — the default on Ubuntu, Fedora and Debian — neither
// hop works that way. /etc/resolv.conf points at 127.0.0.53, which is loopback,
// and the kernel consults the `local` table before any route, so no
// split-default can reach it. Nor does resolved's own upstream query fall into
// the tunnel behind it: that socket is scoped to the link its server belongs
// to, and link scoping overrides the routing table outright.
//
// So true here is the result of a mechanism rather than the absence of a
// problem. bacchus-netd points systemd-resolved's own per-link configuration at
// the tunnel and demotes the physical link, or rewrites /etc/resolv.conf on a
// machine with no resolved, and restores both on teardown and on a client that
// dies without asking. ADR-0051 has the measurement and the argument.
//
// Two things it still does not cover, neither of them platform-specific and
// neither of them what this flag is about: DNS-over-HTTPS or DNS-over-TLS
// configured inside an application (a browser's own resolver, most commonly)
// never emits a UDP/53 query for anything to intercept, on any platform; and a
// process that sends its own queries straight to a hardcoded server is only
// caught by the tunnel's routing, not by this. Windows and macOS answer true
// with exactly the same two exceptions, which is why they do not change the
// answer here.
func DNSCaptureIsComplete() bool { return true }
