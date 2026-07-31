//go:build linux

// The fail-closed kill-switch, as nftables state, spoken over the netfilter
// netlink subsystem.
//
// ADR-0014 decides the policy and ADR-0049 §8 decides two things about the
// Linux shape of it that are easy to get wrong by copying Windows:
//
//   - The lockdown is kernel state, not process state. It survives this helper
//     exiting and it survives the client being killed, which is the entire
//     point: parity item 2 asks for a filter that outlives a killed process,
//     and a killed process is exactly the case a kill-switch exists for.
//   - refreshKillSwitchAllowIP has NO fails-closed window here. ADR-0025
//     records that NetSecurity has no in-place address-list edit, so Windows
//     removes and recreates the allow rule and accepts a brief interval covered
//     only by the default Block. nftables takes an element addition as an
//     atomic transaction, so the Linux implementation adds one element and
//     leaves every rule alone. Porting the Windows dance would manufacture a
//     window the platform does not have.
//
// # The allowlist shape, and why there is no interval set
//
// The obvious encoding for "a set of addresses and CIDRs" is one nftables set
// with `flags interval`, whose elements are start/end pairs. That is the most
// intricate corner of the nftables encoding — overlapping ranges are rejected,
// and every element needs a paired NFT_SET_ELEM_INTERVAL_END marker.
//
// It is also not what this needs, once you look at which entries actually
// arrive late. The live-refresh path (splittunnel.go's learn -> onLearn ->
// refreshKillSwitchAllowIP) only ever carries a single address: bypass
// addresses are learned from DNS A records, and the dynamic set is keyed by
// `v4.String()`. CIDRs only ever appear in the initial allowlist, which is
// built once while the whole table is being created anyway.
//
// So: a plain ipv4_addr set holds host addresses and takes atomic single-
// element additions, and each CIDR in the initial list becomes its own
// masked-compare rule. Both halves use expression types this file needs
// regardless, and the interval encoding is avoided entirely rather than
// written carefully.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	nftTableName = "bacchus"
	nftChainName = "output"
	nftAllowSet  = "allow4"
)

// netfilter netlink constants. Not in x/sys/unix, so they are spelled out here
// against include/uapi/linux/netfilter/nf_tables.h. Every value is a wire
// constant: the kernel's, not ours to choose.
const (
	nfnlSubsysNFTables = 10

	nfnlMsgBatchBegin = 0x10
	nfnlMsgBatchEnd   = 0x11

	nftMsgNewTable   = 0
	nftMsgGetTable   = 1
	nftMsgDelTable   = 2
	nftMsgNewChain   = 3
	nftMsgNewRule    = 6
	nftMsgNewSet     = 9
	nftMsgNewSetElem = 12

	// Attribute ids, per object.
	nftaTableName = 1

	nftaChainTable  = 1
	nftaChainName   = 3
	nftaChainHook   = 4
	nftaChainPolicy = 5
	nftaChainType   = 7

	nftaHookHooknum  = 1
	nftaHookPriority = 2

	nftaRuleTable       = 1
	nftaRuleChain       = 2
	nftaRuleExpressions = 4

	nftaListElem = 1
	nftaExprName = 1
	nftaExprData = 2

	nftaMetaDreg = 1
	nftaMetaKey  = 2

	nftaCmpSreg = 1
	nftaCmpOp   = 2
	nftaCmpData = 3

	nftaImmediateDreg = 1
	nftaImmediateData = 2

	nftaPayloadDreg   = 1
	nftaPayloadBase   = 2
	nftaPayloadOffset = 3
	nftaPayloadLen    = 4

	nftaBitwiseSreg = 1
	nftaBitwiseDreg = 2
	nftaBitwiseLen  = 3
	nftaBitwiseMask = 4
	nftaBitwiseXor  = 5

	nftaLookupSet  = 1
	nftaLookupSreg = 2

	nftaDataValue   = 1
	nftaDataVerdict = 2
	nftaVerdictCode = 1

	nftaSetTable   = 1
	nftaSetName    = 2
	nftaSetKeyType = 4
	nftaSetKeyLen  = 5
	// NFTA_SET_ID is not optional: nf_tables_newset() rejects a set without one
	// with EINVAL, because a set can be referenced by id from elsewhere in the
	// same transaction before it has a handle.
	nftaSetID = 10

	nftaSetElemListTable    = 1
	nftaSetElemListSet      = 2
	nftaSetElemListElements = 3
	nftaSetElemKey          = 1

	// Meta keys, from enum nft_meta_keys. Worth being exact about, because
	// these are dense small integers and a wrong one is ACCEPTED by the kernel
	// as a different, valid comparison rather than rejected: NFT_META_OIF (5)
	// mistyped as 7 becomes NFT_META_OIFNAME and silently compares an interface
	// index against a name, and NFT_META_NFPROTO (15) mistyped as 8 becomes
	// NFT_META_IIFTYPE. Both render visibly wrong in `nft list ruleset`, which
	// is how they were caught, and neither would have failed a test that only
	// checked the transaction succeeded.
	nftMetaOIF     = 5
	nftMetaNFProto = 15
	nftMetaL4Proto = 16

	// Payload bases.
	nftPayloadNetworkHeader   = 1
	nftPayloadTransportHeader = 2

	// Registers. NFT_REG_1 is the legacy 128-bit register the kernel maps onto
	// NFT_REG32_00; using it keeps these messages readable next to `nft --debug`
	// output, which still prints the legacy names.
	nftRegVerdict = 0
	nftReg1       = 1

	nftCmpEQ = 0

	// Verdicts are the netfilter ones, not nftables' negative pseudo-verdicts.
	nfDrop   = 0
	nfAccept = 1

	nfprotoIPv4 = 2

	// Hook: the output path, at the filter priority.
	nfInetLocalOut   = 3
	nfFilterPriority = 0

	// Address family for the table. `inet` covers IPv4 and IPv6 in one chain,
	// so a policy of drop is fail-closed for both — which matters because
	// disablePhysicalIPv6 is best-effort and must not be the only thing
	// standing between a v6-capable network and an uncovered egress path.
	nfprotoInet = 1
)

// nftConn is a netlink socket bound to the netfilter subsystem.
type nftConn struct {
	fd  int
	seq uint32
}

func dialNftables() (*nftConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("netfilter netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netfilter netlink bind: %w", err)
	}
	return &nftConn{fd: fd}, nil
}

func (c *nftConn) Close() error { return unix.Close(c.fd) }

// nftAttr encodes one attribute. Integer values in nftables attributes are
// BIG-endian, unlike rtnetlink's host order — a difference that produces
// messages the kernel accepts and then behaves unexpectedly on, rather than
// rejecting, so it is worth stating once here.
func nftAttr(typ uint16, data []byte) []byte { return attr(typ, data) }

func nftAttrU32(typ uint16, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return nftAttr(typ, b[:])
}

func nftAttrStr(typ uint16, s string) []byte {
	return nftAttr(typ, append([]byte(s), 0))
}

// nftAttrNested wraps children in a nested attribute.
func nftAttrNested(typ uint16, children ...[]byte) []byte {
	var body []byte
	for _, c := range children {
		body = append(body, c...)
	}
	return attr(typ|unix.NLA_F_NESTED, body)
}

// nfgenmsg is the 4-byte header every nftables message carries.
func nfgenmsg(family uint8) []byte {
	b := make([]byte, 4)
	b[0] = family
	b[1] = 0 // version
	binary.BigEndian.PutUint16(b[2:4], 0)
	return b
}

// nftMsg is one message inside a batch.
type nftMsg struct {
	typ   uint16 // NFT_MSG_*
	flags uint16
	body  []byte
}

// batch sends every message as one atomic nftables transaction.
//
// Atomicity is the property being bought here, and it is why arming is not a
// sequence of steps that can half-apply. Either the table, the chain with its
// drop policy, the set and every allow rule all exist, or none of them do.
// There is no ordering in which the machine is briefly locked down with no
// allow rules — which, with the default already flipped to drop, would take the
// user's network out from under the very session that is arming it.
func (c *nftConn) batch(msgs []nftMsg) error {
	if len(msgs) == 0 {
		return nil
	}
	var out []byte
	base := c.seq

	appendMsg := func(typ uint16, flags uint16, body []byte) {
		c.seq++
		m := make([]byte, unix.NLMSG_HDRLEN+len(body))
		binary.NativeEndian.PutUint32(m[0:4], uint32(len(m)))
		binary.NativeEndian.PutUint16(m[4:6], typ)
		binary.NativeEndian.PutUint16(m[6:8], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
		binary.NativeEndian.PutUint32(m[8:12], c.seq)
		binary.NativeEndian.PutUint32(m[12:16], 0)
		copy(m[unix.NLMSG_HDRLEN:], body)
		out = append(out, m...)
	}

	// The batch envelope's res_id names the subsystem the batch belongs to.
	envelope := make([]byte, 4)
	envelope[0] = unix.AF_UNSPEC
	binary.BigEndian.PutUint16(envelope[2:4], nfnlSubsysNFTables)

	appendMsg(nfnlMsgBatchBegin, 0, envelope)
	for _, m := range msgs {
		appendMsg(nfnlSubsysNFTables<<8|m.typ, m.flags, m.body)
	}
	appendMsg(nfnlMsgBatchEnd, 0, envelope)
	last := c.seq

	if err := unix.Sendto(c.fd, out, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("nftables send: %w", err)
	}

	// Collect acknowledgements until the batch-end message is acked. A failure
	// anywhere aborts the whole transaction, so the first non-zero errno is the
	// answer for the batch.
	buf := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("nftables receive: %w", err)
		}
		parsed, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return fmt.Errorf("nftables parse: %w", err)
		}
		for _, m := range parsed {
			if m.Header.Seq <= base || m.Header.Seq > last {
				continue
			}
			if m.Header.Type != unix.NLMSG_ERROR {
				continue
			}
			if len(m.Data) < 4 {
				return errors.New("nftables: truncated error message")
			}
			if code := int32(binary.NativeEndian.Uint32(m.Data[0:4])); code != 0 {
				return fmt.Errorf("nftables transaction: %w", unix.Errno(-code))
			}
			if m.Header.Seq == last {
				return nil
			}
		}
	}
}

// -------------------------------------------------------------------------
// Expressions
// -------------------------------------------------------------------------

func expr(name string, data []byte) []byte {
	return nftAttrNested(nftaListElem,
		nftAttrStr(nftaExprName, name),
		nftAttrNested(nftaExprData, data),
	)
}

// exprMetaLoad loads a meta key into reg 1.
func exprMetaLoad(key uint32) []byte {
	return expr("meta", concat(
		nftAttrU32(nftaMetaKey, key),
		nftAttrU32(nftaMetaDreg, nftReg1),
	))
}

// exprCmpEq compares reg 1 against a literal.
func exprCmpEq(value []byte) []byte {
	return expr("cmp", concat(
		nftAttrU32(nftaCmpSreg, nftReg1),
		nftAttrU32(nftaCmpOp, nftCmpEQ),
		nftAttrNested(nftaCmpData, nftAttr(nftaDataValue, value)),
	))
}

// exprPayloadLoad loads len bytes at offset from a header base into reg 1.
func exprPayloadLoad(base, offset, length uint32) []byte {
	return expr("payload", concat(
		nftAttrU32(nftaPayloadDreg, nftReg1),
		nftAttrU32(nftaPayloadBase, base),
		nftAttrU32(nftaPayloadOffset, offset),
		nftAttrU32(nftaPayloadLen, length),
	))
}

// exprBitwiseMask ANDs reg 1 with mask, in place. XOR is required by the
// kernel even when it is zero.
func exprBitwiseMask(mask []byte) []byte {
	zero := make([]byte, len(mask))
	return expr("bitwise", concat(
		nftAttrU32(nftaBitwiseSreg, nftReg1),
		nftAttrU32(nftaBitwiseDreg, nftReg1),
		nftAttrU32(nftaBitwiseLen, uint32(len(mask))),
		nftAttrNested(nftaBitwiseMask, nftAttr(nftaDataValue, mask)),
		nftAttrNested(nftaBitwiseXor, nftAttr(nftaDataValue, zero)),
	))
}

// exprLookup matches reg 1 against a named set.
func exprLookup(set string) []byte {
	return expr("lookup", concat(
		nftAttrStr(nftaLookupSet, set),
		nftAttrU32(nftaLookupSreg, nftReg1),
	))
}

// exprVerdict terminates a rule.
func exprVerdict(code uint32) []byte {
	return expr("immediate", concat(
		nftAttrU32(nftaImmediateDreg, nftRegVerdict),
		nftAttrNested(nftaImmediateData,
			nftAttrNested(nftaDataVerdict, nftAttrU32(nftaVerdictCode, code)),
		),
	))
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// rule builds a NEWRULE message from a list of expressions.
func rule(exprs ...[]byte) nftMsg {
	return nftMsg{
		typ:   nftMsgNewRule,
		flags: unix.NLM_F_CREATE | unix.NLM_F_APPEND,
		body: concat(
			nfgenmsg(nfprotoInet),
			nftAttrStr(nftaRuleTable, nftTableName),
			nftAttrStr(nftaRuleChain, nftChainName),
			nftAttrNested(nftaRuleExpressions, concat(exprs...)),
		),
	}
}

// -------------------------------------------------------------------------
// Arming, lifting, recovering
// -------------------------------------------------------------------------

// killSwitchSpec is everything the lockdown needs, all of it derived on this
// side of the boundary except the address lists, which arrive parsed.
type killSwitchSpec struct {
	TunIfIndex int
	LoIfIndex  int
	Hosts      []netip.Addr   // single addresses: control plane, bypass hosts, learned
	Nets       []netip.Prefix // CIDR bypass entries
}

// enableKillSwitch builds the whole lockdown as one transaction.
func (c *nftConn) enableKillSwitch(spec killSwitchSpec) error {
	msgs := []nftMsg{
		// Table.
		{typ: nftMsgNewTable, flags: unix.NLM_F_CREATE, body: concat(
			nfgenmsg(nfprotoInet),
			nftAttrStr(nftaTableName, nftTableName),
		)},
		// Output chain, policy drop. This is the fail-closed default: every
		// rule below is an exception to it, so a rule that fails to encode
		// blocks traffic rather than letting it out.
		{typ: nftMsgNewChain, flags: unix.NLM_F_CREATE, body: concat(
			nfgenmsg(nfprotoInet),
			nftAttrStr(nftaChainTable, nftTableName),
			nftAttrStr(nftaChainName, nftChainName),
			nftAttrNested(nftaChainHook,
				nftAttrU32(nftaHookHooknum, nfInetLocalOut),
				nftAttrU32(nftaHookPriority, nfFilterPriority),
			),
			nftAttrStr(nftaChainType, "filter"),
			nftAttrU32(nftaChainPolicy, nfDrop),
		)},
		// The allowlist set.
		{typ: nftMsgNewSet, flags: unix.NLM_F_CREATE, body: concat(
			nfgenmsg(nfprotoInet),
			nftAttrStr(nftaSetTable, nftTableName),
			nftAttrStr(nftaSetName, nftAllowSet),
			nftAttrU32(nftaSetKeyType, 7), // NFT_TYPE_IPADDR, userspace metadata
			nftAttrU32(nftaSetKeyLen, 4),
			nftAttrU32(nftaSetID, 1),
		)},
	}

	if elems := setElemMsg(spec.Hosts); elems != nil {
		msgs = append(msgs, *elems)
	}

	// Everything on the tunnel adapter: this is what makes tunnelled traffic
	// work at all under lockdown.
	msgs = append(msgs, rule(
		exprMetaLoad(nftMetaOIF),
		exprCmpEq(hostU32(uint32(spec.TunIfIndex))),
		exprVerdict(nfAccept),
	))
	// Loopback: the local SOCKS server the netstack dials.
	msgs = append(msgs, rule(
		exprMetaLoad(nftMetaOIF),
		exprCmpEq(hostU32(uint32(spec.LoIfIndex))),
		exprVerdict(nfAccept),
	))
	// The allowlist, guarded on nfproto so the IPv4 daddr offset is only
	// applied to IPv4 packets.
	msgs = append(msgs, rule(
		exprMetaLoad(nftMetaNFProto),
		exprCmpEq([]byte{nfprotoIPv4}),
		exprPayloadLoad(nftPayloadNetworkHeader, 16, 4),
		exprLookup(nftAllowSet),
		exprVerdict(nfAccept),
	))
	// One masked compare per CIDR entry.
	for _, n := range spec.Nets {
		mask := net4Mask(n.Bits())
		network := n.Masked().Addr().As4()
		msgs = append(msgs, rule(
			exprMetaLoad(nftMetaNFProto),
			exprCmpEq([]byte{nfprotoIPv4}),
			exprPayloadLoad(nftPayloadNetworkHeader, 16, 4),
			exprBitwiseMask(mask),
			exprCmpEq(network[:]),
			exprVerdict(nfAccept),
		))
	}
	// DHCP, so the physical lease does not lapse out from under the tunnel.
	// There is deliberately no plaintext-DNS allowance to match: DNS is
	// resolved over TCP through the tunnel, so the lockdown cannot leak a
	// lookup. That omission is the same one killswitch_windows.go documents.
	msgs = append(msgs, rule(
		exprMetaLoad(nftMetaL4Proto),
		exprCmpEq([]byte{unix.IPPROTO_UDP}),
		exprPayloadLoad(nftPayloadTransportHeader, 0, 2),
		exprCmpEq(bePort(68)),
		exprPayloadLoad(nftPayloadTransportHeader, 2, 2),
		exprCmpEq(bePort(67)),
		exprVerdict(nfAccept),
	))

	return c.batch(msgs)
}

// setElemMsg builds one NEWSETELEM message for a batch of addresses.
func setElemMsg(addrs []netip.Addr) *nftMsg {
	var elems []byte
	n := 0
	for _, a := range addrs {
		if !a.Is4() {
			continue
		}
		b := a.As4()
		elems = append(elems, nftAttrNested(nftaListElem,
			nftAttrNested(nftaSetElemKey, nftAttr(nftaDataValue, b[:])),
		)...)
		n++
	}
	if n == 0 {
		return nil
	}
	return &nftMsg{
		typ:   nftMsgNewSetElem,
		flags: unix.NLM_F_CREATE,
		body: concat(
			nfgenmsg(nfprotoInet),
			nftAttrStr(nftaSetElemListTable, nftTableName),
			nftAttrStr(nftaSetElemListSet, nftAllowSet),
			nftAttrNested(nftaSetElemListElements, elems),
		),
	}
}

// refreshAllowIP folds one late-learned address into the live allowlist.
//
// This is ADR-0049 §8's "no fails-closed window" in one function: a single
// element addition, in its own transaction, touching no rule. Nothing is
// removed, so there is no interval during which the addresses this allowlist
// covers are uncovered.
func (c *nftConn) refreshAllowIP(addr netip.Addr) error {
	msg := setElemMsg([]netip.Addr{addr})
	if msg == nil {
		return nil
	}
	err := c.batch([]nftMsg{*msg})
	// Already present is the normal case for a re-learned address.
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

// deleteTable lifts the lockdown: one transaction, whole table.
func (c *nftConn) deleteTable() error {
	err := c.batch([]nftMsg{{
		typ:   nftMsgDelTable,
		flags: 0,
		body: concat(
			nfgenmsg(nfprotoInet),
			nftAttrStr(nftaTableName, nftTableName),
		),
	}})
	if errors.Is(err, unix.ENOENT) {
		return nil // not armed
	}
	return err
}

// tableExists reports whether this helper's own table is present. That is the
// whole of parity item 3's detection question on Linux, and it lands more
// cleanly here than on Windows: the table is ours by name, so there is no
// heuristic about whose lockdown a given piece of firewall state is.
func (c *nftConn) tableExists() (bool, error) {
	c.seq++
	seq := c.seq
	body := concat(nfgenmsg(nfprotoInet), nftAttrStr(nftaTableName, nftTableName))

	m := make([]byte, unix.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(m[0:4], uint32(len(m)))
	binary.NativeEndian.PutUint16(m[4:6], nfnlSubsysNFTables<<8|nftMsgGetTable)
	binary.NativeEndian.PutUint16(m[6:8], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(m[8:12], seq)
	copy(m[unix.NLMSG_HDRLEN:], body)

	if err := unix.Sendto(c.fd, m, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, err
	}
	buf := make([]byte, 32*1024)
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return false, err
		}
		parsed, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return false, err
		}
		for _, msg := range parsed {
			if msg.Header.Seq != seq {
				continue
			}
			if msg.Header.Type == unix.NLMSG_ERROR {
				if len(msg.Data) < 4 {
					return false, errors.New("nftables: truncated error message")
				}
				code := int32(binary.NativeEndian.Uint32(msg.Data[0:4]))
				if code == 0 {
					return true, nil
				}
				if unix.Errno(-code) == unix.ENOENT {
					return false, nil
				}
				return false, unix.Errno(-code)
			}
			// A NEWTABLE reply means it is there.
			return true, nil
		}
	}
}

// hostU32 renders an interface index the way meta comparisons expect it: meta
// loads oif in HOST byte order, unlike the attribute values around it.
func hostU32(v uint32) []byte {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return b[:]
}

// bePort renders a port as it appears in the packet: network byte order.
func bePort(p uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return b[:]
}

func net4Mask(bits int) []byte {
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], ^uint32(0)<<(32-bits))
	if bits == 0 {
		return []byte{0, 0, 0, 0}
	}
	return m[:]
}
