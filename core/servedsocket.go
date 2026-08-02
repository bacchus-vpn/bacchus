// The sockets this node opens on OTHER PEOPLE's behalf, and the one thing that
// has to be true of them that is not true of any other socket here: they must
// leave by this machine's own address (issue #109).
//
// # Why a served socket is a different kind of socket
//
// Everything else this engine dials is its own business — a coordinator link, a
// transport underlay, a client's SOCKS connection. A served socket is not. An
// exit's egress to the internet and a relay's onward dial to the next hop carry
// somebody else's traffic, and the exit opt-in tells its operator, in the
// settings window, that it leaves "under YOUR own IP and jurisdiction".
//
// On a machine that also routes itself through Bacchus, that sentence is false
// unless something makes it true. The client installs the OS default route into
// its own TUN, so a served dial made the ordinary way is captured by it: other
// people's traffic goes out through this machine's own Bacchus connection and
// egresses at the UPSTREAM exit's address. A volunteer accepts a legal exposure
// they do not actually have, while somebody else's traffic launders through an
// exit its operator never agreed to carry it for. That is worse than the
// feature not existing, which is why clients/fyne refused to offer it at all
// until this existed (appstate.ErrVolunteerWhileRouted).
//
// # Why binding the source is the whole client-side mechanism
//
// Served traffic and the operator's own traffic go to the SAME destinations and
// are indistinguishable by address, so no destination-based rule — split
// tunnelling included — can tell them apart. The socket is the only thing that
// can, and this package owns the served ones.
//
// What marks them has to be something an unprivileged process can set on its
// own socket, which rules out the obvious answer. SO_MARK is the natural fit
// and it is not available: setting it needs CAP_NET_ADMIN, or CAP_NET_RAW since
// Linux 5.17, and this engine runs inside an ordinary desktop GUI that has
// neither. Binding a local address needs no privilege at all. So the mark is a
// source address, and the platform side turns "packets from this address" back
// into "out the physical interface" (ADR-0053 §2).
//
// This is not per-app classification and does not reopen ADR-0025's scope cut.
// A process choosing the source address of its own sockets is a different thing
// from a system classifying somebody else's traffic.
//
// # What is deliberately NOT bound
//
// The exit's listener (Engine.Start) stays on the wildcard address. It does not
// need this: an inbound connection arrives ON this machine's own address, so
// the accepted socket already has it as its local address and the reply carries
// it as the source — the same thing binding would have produced, without
// narrowing which address an operator can be reached at. Reachability was the
// second half of what made serving-while-routed impossible, and the platform's
// carve-out fixes it without a change here.
package core

import (
	"fmt"
	"net"
	"time"
)

// servedSource is the local address served sockets bind, or nil when this node
// is not serving through a tunnel it also routes itself through — which is
// every node with no device-wide enforcement, and every node built before
// issue #109.
func (e *Engine) servedSource() net.IP {
	if e.cfg.ServedSource == nil {
		return nil
	}
	s := e.cfg.ServedSource()
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

// dialServed opens a TCP connection that carries somebody else's traffic.
//
// With no served source configured this is exactly net.DialTimeout, which is
// what the four call sites did before issue #109 and what they still do on a
// node that is not routing itself.
//
// With one, note what happens to a destination that is IPv6-only: the dial
// fails rather than falling back to an unbound one. That is the fail-closed
// direction and it is worth being explicit about, because the alternative looks
// more helpful and is not. An unbound retry would put that connection back into
// the tunnel — the exact egress-under-the-upstream-exit's-address this whole
// file exists to prevent — for the one destination class where the carve-out
// does not reach, and the operator would never know which of their sessions had
// silently gone the wrong way. A refused dial is a session that does not
// happen. It is also not a new limitation in practice: enforcement disables
// IPv6 on the physical interface for the tunnel's lifetime (ADR-0039 parity
// item 6), so this machine has no IPv6 egress to serve with either way.
//
// The refusal comes from the standard library rather than from a check here.
// net.Dialer filters the resolved address list to the local address's family
// and reports "no suitable address found" when nothing matches, so a v6-only
// destination is refused before a packet is sent.
func (e *Engine) dialServed(network, addr string, timeout time.Duration) (net.Conn, error) {
	src := e.servedSource()
	if src == nil {
		return net.DialTimeout(network, addr, timeout)
	}
	d := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: src}}
	return d.Dial(network, addr)
}

// dialServedUDP is the same for the exit's UDP egress.
//
// Separate from dialServed rather than folded into it because the UDP relay
// needs a *net.UDPConn — it hand-rolls a datagram loop with ReadFrom/WriteTo
// rather than copying a stream — and a net.Conn from a Dialer would have to be
// type-asserted back. The family mismatch that dialServed leaves to the
// standard library has to be checked here, because net.DialUDP takes an
// already-resolved address and will bind the mismatched pair rather than
// filtering it: the same fail-closed answer, reached explicitly.
func (e *Engine) dialServedUDP(raddr *net.UDPAddr) (*net.UDPConn, error) {
	src := e.servedSource()
	if src == nil {
		return net.DialUDP("udp", nil, raddr)
	}
	if (src.To4() != nil) != (raddr.IP.To4() != nil) {
		return nil, fmt.Errorf("core: serving %s needs a source address of the same family as %s", raddr.IP, src)
	}
	return net.DialUDP("udp", &net.UDPAddr{IP: src}, raddr)
}
