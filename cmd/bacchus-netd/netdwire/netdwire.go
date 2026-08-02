// Package netdwire is the wire protocol between clients/fyne (unprivileged)
// and bacchus-netd (root). ADR-0049 fixes the vocabulary and the validation
// rules and leaves the serialization to this package; what follows is that
// serialization, and nothing else — no netlink, no policy, no privilege.
//
// # Why this package sits under cmd/
//
// It is shared by exactly two callers on opposite sides of a privilege
// boundary: cmd/bacchus-netd (the helper) and clients/internal/enforcement
// (the client stub). It cannot live with the stub, because Go's internal-import
// rule scopes clients/internal/... to clients/ and the helper is not under
// clients/. So it lives with the helper, which is the side that defines the
// protocol and enforces it. Every other cmd/ in this repo is a flat main
// package; this is the first with a subpackage, and the import rule is the
// whole reason.
//
// # The frame
//
// One request per frame, one reply per frame: a 4-byte big-endian length
// followed by that many bytes of JSON. JSON rather than a hand-rolled binary
// encoding because the parser runs as ROOT — encoding/json is stdlib and
// well-tested, a hand-rolled decoder in a root process is a new attack surface
// written for this one use, and the message set is small enough that the
// encoding's cost is irrelevant next to that.
//
// Framing has hard caps (MaxFrame, MaxList) because the peer is untrusted by
// construction: an unprivileged local process that can reach the socket can
// send whatever it likes, and "the helper allocated a gigabyte because the
// length prefix said so" is a denial of service against the machine's
// networking, run as root. The caps are checked before any allocation.
//
// # What may cross inward
//
// ADR-0049 §2 fixes this and it is deliberately narrower than the osNet
// interface it serves: IP prefixes as strings (parsed on the privileged side,
// never interpolated), one IPv4 address and prefix length for the TUN, lists of
// IP addresses for the kill-switch allowlist, and a session token. That is the
// whole vocabulary.
//
// Two osNet parameters are deliberately NOT represented here, and their absence
// is the point rather than an oversight:
//
//   - gatewayInfo. addExclusionRoutes takes one, but osn.defaultGateway() is
//     the package's sole non-test producer of the type, so a gatewayInfo
//     arriving at the helper would always be an echo of what the helper itself
//     just produced. Treating it as input would let a compromised client aim
//     exclusion routes at an attacker-chosen LAN gateway using a parameter that
//     carries no information the helper lacks. It crosses OUTWARD only — see
//     Gateway on Reply.
//   - tunNextHop and ifAlias. Same reasoning: the helper created the TUN and
//     read the default route, so it already knows both, and an interface named
//     by the client is an interface of the client's choosing.
package netdwire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version. ADR-0049's Consequences require that a
// helper and a GUI that disagree refuse each other outright rather than
// negotiate down to a subset: "a client that silently loses the kill-switch
// because the helper is old is parity item 7's failure mode wearing a version
// skew." So this is compared for equality, not for ">=", and there is
// deliberately no capability handshake to fall back through.
const Version = 1

const (
	// MaxFrame caps one encoded request or reply. The largest legitimate
	// message is a kill-switch allowlist: control-plane endpoints plus the
	// bypass set, each an IP or CIDR string. MaxList entries at ~44 bytes for
	// an IPv6 CIDR plus JSON quoting is comfortably inside this.
	MaxFrame = 1 << 16

	// MaxList caps how many prefixes or addresses one request may carry, so a
	// frame that fits MaxFrame still cannot make the helper do unbounded work
	// per request.
	MaxList = 512
)

// Verb is the closed set of operations. One per privileged osNet method, plus
// the two that bracket a session. A verb outside this set is refused by name
// (CodeUnknownVerb) rather than ignored: silence would let a client that
// believes it armed a kill-switch carry on believing it.
type Verb string

const (
	// VerbOpen starts a session and returns a token. Every mutating verb below
	// must carry that token.
	VerbOpen Verb = "open"
	// VerbClose ends a session cleanly. Distinct from the connection dropping,
	// which is the crash signal (ADR-0049 §8) and holds the lockdown.
	VerbClose Verb = "close"

	VerbDefaultGateway       Verb = "default-gateway"
	VerbAddExclusionRoutes   Verb = "add-exclusion-routes"
	VerbAddExclusionRoutesV6 Verb = "add-exclusion-routes-v6"
	VerbAddInclusionRoutes   Verb = "add-inclusion-routes"
	VerbRemoveRoutes         Verb = "remove-routes"
	VerbCreateTUN            Verb = "create-tun"
	VerbConfigureTUN         Verb = "configure-tun"
	VerbAddSplitDefaultRoute Verb = "add-split-default-route"
	VerbDisablePhysicalIPv6  Verb = "disable-physical-ipv6"
	VerbEnablePhysicalIPv6   Verb = "enable-physical-ipv6"
	VerbEnableKillSwitch     Verb = "enable-kill-switch"
	VerbDisableKillSwitch    Verb = "disable-kill-switch"
	VerbRecoverKillSwitch    Verb = "recover-kill-switch"
	VerbRefreshAllowIP       Verb = "refresh-kill-switch-allow-ip"

	// VerbCaptureDNS points the machine's resolver at the tunnel; VerbReleaseDNS
	// puts it back (ADR-0051). Both carry no fields beyond the token: the helper
	// derives the address it points the resolver at from the TUN it created, so
	// no interface name, unit name or file path crosses inward for this.
	//
	// Note these are additions to the verb SET, not to Request. That matters
	// for skew in a way the reverse would not: ReadRequest decodes with unknown
	// fields refused, so a new field would be a hard parse failure against an
	// old helper, while a new verb is a clean CodeUnknownVerb. Neither can
	// actually be reached, because Version is compared for equality at Open and
	// an old helper refuses the session outright — but the protocol degrades
	// legibly rather than confusingly if that ever changes.
	VerbCaptureDNS Verb = "capture-dns"
	VerbReleaseDNS Verb = "release-dns"
)

// Error codes. These are part of the protocol rather than free text because
// the client stub branches on two of them — CodeVersion and CodeBusy produce
// different user-facing advice — and because a refusal that a test can assert
// by code does not become untestable the day someone rewords the message.
const (
	CodeBadRequest  = "bad-request"  // malformed frame, bad prefix, missing field
	CodeUnknownVerb = "unknown-verb" // not in the set above
	CodeVersion     = "version"      // helper and client disagree on Version
	CodeNoSession   = "no-session"   // mutating verb with no session open
	CodeBadToken    = "bad-token"    // token missing or not this session's
	CodeBusy        = "busy"         // another client already holds the session
	CodeDenied      = "denied"       // peer credential check failed
	CodeInternal    = "internal"     // the privileged operation itself failed
)

// Request is one call. Fields are shared across verbs rather than split into a
// type per verb: the set is small, every field is optional-by-verb, and one
// struct keeps the decode path — the part that runs as root — to a single
// json.Unmarshal with a single set of caps applied afterwards.
type Request struct {
	Version int    `json:"version"`
	Verb    Verb   `json:"verb"`
	Token   string `json:"token,omitempty"`

	// Prefixes carries the destinations for the four route verbs. Strings on
	// the wire, netip.Prefix on the privileged side — parsed, never
	// interpolated, because there is no command line for them to be
	// interpolated into (ADR-0049 §4).
	Prefixes []string `json:"prefixes,omitempty"`

	// Control and Bypass are the kill-switch allowlist halves, kept separate
	// because they come from different places and the helper logs them
	// differently, not because it treats them differently.
	Control []string `json:"control,omitempty"`
	Bypass  []string `json:"bypass,omitempty"`

	// Addr and PrefixLen configure the TUN interface. Addr is also sent with
	// VerbAddSplitDefaultRoute, where the helper already knows it — see
	// ADR-0049 §3.5. It is checked for equality with the session's configured
	// address there rather than used, which turns a redundant parameter into a
	// consistency check instead of a second source of truth.
	Addr      string `json:"addr,omitempty"`
	PrefixLen int    `json:"prefix_len,omitempty"`

	// IP is the single late-learned bypass address for VerbRefreshAllowIP.
	IP string `json:"ip,omitempty"`
}

// Gateway is gatewayInfo crossing outward. Every field is derived by the
// helper from the kernel's own routing table; none of it is ever accepted back.
type Gateway struct {
	NextHop   string `json:"next_hop"`
	IfIndex   int    `json:"if_index"`
	IfAlias   string `json:"if_alias"`
	NextHopV6 string `json:"next_hop_v6,omitempty"`
}

// Reply is one answer. OK false always carries a Code and an Error.
type Reply struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`

	// Token is set only by a successful VerbOpen.
	Token string `json:"token,omitempty"`

	// Gateway is set only by a successful VerbDefaultGateway.
	Gateway *Gateway `json:"gateway,omitempty"`

	// TUNCreated marks the reply that carries a file descriptor out of band
	// via SCM_RIGHTS. The fd is not in the JSON — it cannot be — so a reader
	// needs to know whether to expect one, and an fd arriving with a reply
	// that did not set this is a protocol violation rather than a bonus.
	TUNCreated bool `json:"tun_created,omitempty"`
}

// ProtocolError is a refusal carrying its code, so callers can branch without
// matching on message text.
type ProtocolError struct {
	Code    string
	Message string
}

func (e *ProtocolError) Error() string { return e.Message }

// Errorf builds a refusal.
func Errorf(code, format string, args ...any) *ProtocolError {
	return &ProtocolError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ErrFrameTooLarge is returned before any allocation when a length prefix
// exceeds MaxFrame.
var ErrFrameTooLarge = errors.New("netdwire: frame exceeds maximum size")

// frameBytes encodes v as one complete length-prefixed frame in a single
// buffer. Separate from WriteFrame because the fd-passing path must hand the
// whole frame to one sendmsg call (see SendReplyWithFD) — the descriptor and
// the bytes it belongs to have to travel together.
func frameBytes(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out, nil
}

// decodeFrame decodes one complete frame already held in a single buffer, for
// the fd-passing read path where the frame arrived in one recvmsg.
func decodeFrame(b []byte) (*Reply, error) {
	if len(b) < 4 {
		return nil, errors.New("netdwire: truncated frame header")
	}
	n := binary.BigEndian.Uint32(b[:4])
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	if int(n) != len(b)-4 {
		return nil, fmt.Errorf("netdwire: frame length %d does not match %d bytes read", n, len(b)-4)
	}
	var rep Reply
	if err := json.Unmarshal(b[4:], &rep); err != nil {
		return nil, fmt.Errorf("malformed reply: %w", err)
	}
	return &rep, nil
}

// WriteFrame encodes v as one length-prefixed JSON frame.
func WriteFrame(w io.Writer, v any) error {
	out, err := frameBytes(v)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

// readFrame reads one length-prefixed frame's body. The length is checked
// against MaxFrame BEFORE the buffer is allocated: the whole point of the cap
// is that a hostile length prefix must not be able to make a root process
// allocate, so validating after make() would defeat it.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// ReadRequest reads and decodes one request, applying every cap and
// well-formedness rule that does not require privileged state. Unknown fields
// are refused rather than ignored: this decodes attacker-controlled input in a
// root process, and silently dropping a field the sender thought mattered is
// how a version skew turns into a wrong-but-accepted request.
func ReadRequest(r io.Reader) (*Request, error) {
	body, err := readFrame(r)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return nil, Errorf(CodeBadRequest, "malformed request: %v", err)
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	return &req, nil
}

// validate applies the encoding-level rules. Semantic validation — is this
// prefix parseable, does this token match, is a session open — belongs to the
// helper, which is the side with the state to answer it.
func (r *Request) validate() error {
	if r.Version != Version {
		return Errorf(CodeVersion,
			"protocol version mismatch: helper speaks %d, client sent %d — install matching bacchus-netd and bacchus-fyne",
			Version, r.Version)
	}
	if r.Verb == "" {
		return Errorf(CodeBadRequest, "request has no verb")
	}
	for _, l := range [][]string{r.Prefixes, r.Control, r.Bypass} {
		if len(l) > MaxList {
			return Errorf(CodeBadRequest, "list exceeds %d entries", MaxList)
		}
	}
	return nil
}

// ReadReply reads and decodes one reply. Unknown fields are tolerated here,
// unlike ReadRequest: this runs in the unprivileged client against a helper it
// already refused to talk to on any version mismatch, so strictness buys
// nothing and would turn a harmless additive field into a hard failure.
func ReadReply(r io.Reader) (*Reply, error) {
	body, err := readFrame(r)
	if err != nil {
		return nil, err
	}
	var rep Reply
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, fmt.Errorf("malformed reply: %w", err)
	}
	return &rep, nil
}

// Err returns the reply's refusal as an error, or nil if it succeeded.
func (r *Reply) Err() error {
	if r.OK {
		return nil
	}
	msg := r.Error
	if msg == "" {
		msg = "bacchus-netd refused the request"
	}
	return &ProtocolError{Code: r.Code, Message: msg}
}

// Failf builds a refusal reply.
func Failf(code, format string, args ...any) *Reply {
	return &Reply{OK: false, Code: code, Error: fmt.Sprintf(format, args...)}
}
