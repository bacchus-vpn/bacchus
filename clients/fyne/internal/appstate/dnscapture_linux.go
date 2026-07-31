//go:build linux

package appstate

// DNSCaptureIsComplete reports whether this platform captures EVERY DNS query
// a connected device makes. False means the settings window must say so next to
// the DNS field rather than let its "these change what leaves it" notice cover
// a field it does not fully cover.
//
// Linux has one and it is not small. DNS is intercepted portably, inside the
// netstack (tun2socks.go's handleDNSUDP sees UDP/53 and resolves it over
// DNS-over-TCP through the tunnel), which works whenever the resolver's
// configured server is an ordinary routable address: the query leaves the
// stack, meets the split-default route, and enters the TUN where the
// interceptor sees it.
//
// On a systemd-resolved machine — the default on Ubuntu, Fedora and Debian —
// /etc/resolv.conf points at 127.0.0.53, which is loopback. No route can
// capture it: the kernel consults the `local` table before anything else, so a
// 0.0.0.0/1 + 128.0.0.0/1 split-default cannot override 127.0.0.0/8. Those
// queries never reach the TUN and the interceptor never sees them. With the
// kill-switch armed resolved's own upstream query is dropped (the allowlist
// deliberately has no plaintext-DNS allowance) and the machine has a tunnel and
// no working DNS; without it, that query goes out in the clear.
//
// Closing this needs a new osNet primitive, which is a change to shared code
// Windows and macOS also implement — bacchus#104, deliberately out of scope for
// the change that built the helper, the protocol and the backend. Until it
// lands, the honest thing is to say so where the setting is, rather than let
// the window's "these change what leaves it" notice cover a field it does not
// cover. The bar is that the UI never claims more than it enforces.
func DNSCaptureIsComplete() bool { return false }
