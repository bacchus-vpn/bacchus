package capacity

import (
	"fmt"
	"strconv"
	"strings"
)

// Rate is a transfer rate in bits per second. Bits, not bytes, because that is
// the unit every ISP states a line speed in — an operator reading "20 Mbit" off
// their contract must be able to type it back verbatim. The zero Rate means
// unlimited (see Limits).
type Rate uint64

// Bytes is a byte count. Bytes, not bits, because that is the unit every ISP
// states a monthly cap in ("400 GB"). The unit split between Rate and Bytes is
// deliberate and mirrors the operator's own paperwork rather than being
// internally uniform: a config the operator can transcribe without a factor-of-8
// conversion is one they cannot get wrong by a factor of 8.
type Bytes uint64

// Common rate and size units. Decimal (10^3), not binary (2^10), because ISPs
// bill in decimal: a "500 GB" cap is 500e9 bytes, and using 2^30 here would
// silently let a node overshoot its real cap by 7.4%.
const (
	Kbit Rate = 1_000
	Mbit Rate = 1_000 * Kbit
	Gbit Rate = 1_000 * Mbit

	KB Bytes = 1_000
	MB Bytes = 1_000 * KB
	GB Bytes = 1_000 * MB
	TB Bytes = 1_000 * GB
)

// rateUnits and byteUnits are the suffixes ParseRate/ParseBytes accept. Lookup is
// exact-match on the whole suffix (parseUnit splits the number off first), so the
// order here is presentational only — no prefix ever shadows another.
var (
	rateUnits = []struct {
		suffix string
		mult   Rate
	}{
		{"gbit", Gbit}, {"mbit", Mbit}, {"kbit", Kbit},
		{"gbps", Gbit}, {"mbps", Mbit}, {"kbps", Kbit},
		{"g", Gbit}, {"m", Mbit}, {"k", Kbit},
		{"bit", 1}, {"", 1},
	}
	byteUnits = []struct {
		suffix string
		mult   Bytes
	}{
		{"tb", TB}, {"gb", GB}, {"mb", MB}, {"kb", KB},
		{"t", TB}, {"g", GB}, {"m", MB}, {"k", KB},
		{"b", 1}, {"", 1},
	}
)

// ParseRate parses an operator-facing line speed such as "20Mbit", "1.5 Gbit",
// "100mbps" or a bare "20000000" (bits/s). Case and internal spaces are ignored.
// "" and "0" parse to 0, which Limits reads as unlimited.
//
// A fractional value is accepted ("1.5Gbit") because contracts are written that
// way; it is rounded down to whole bits/s, which for any real line speed is a
// rounding error of less than one bit.
func ParseRate(s string) (Rate, error) {
	v, mult, err := parseUnit(s, func(suffix string) (uint64, bool) {
		for _, u := range rateUnits {
			if suffix == u.suffix {
				return uint64(u.mult), true
			}
		}
		return 0, false
	})
	if err != nil {
		return 0, fmt.Errorf("parse rate %q: %w (want e.g. 20Mbit, 1.5Gbit, 100kbit)", s, err)
	}
	return Rate(v * float64(mult)), nil
}

// ParseBytes parses an operator-facing data cap such as "400GB", "1.5 TB",
// "500g" or a bare byte count. Units are decimal (400GB = 400e9), matching how
// an ISP states a cap. "" and "0" parse to 0, which Limits reads as unlimited.
func ParseBytes(s string) (Bytes, error) {
	v, mult, err := parseUnit(s, func(suffix string) (uint64, bool) {
		for _, u := range byteUnits {
			if suffix == u.suffix {
				return uint64(u.mult), true
			}
		}
		return 0, false
	})
	if err != nil {
		return 0, fmt.Errorf("parse size %q: %w (want e.g. 400GB, 1.5TB, 250MB)", s, err)
	}
	return Bytes(v * float64(mult)), nil
}

// parseUnit splits s into a numeric part and a unit suffix and resolves the
// suffix through lookup. Shared by ParseRate and ParseBytes so both accept
// spaces, mixed case, and a bare number identically.
func parseUnit(s string, lookup func(string) (uint64, bool)) (float64, uint64, error) {
	t := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if t == "" {
		return 0, 1, nil
	}
	// Split at the first character that cannot be part of the number.
	i := 0
	for i < len(t) && (t[i] == '.' || (t[i] >= '0' && t[i] <= '9')) {
		i++
	}
	num, suffix := t[:i], t[i:]
	if num == "" {
		return 0, 0, fmt.Errorf("no number")
	}
	v, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("bad number %q", num)
	}
	if v < 0 {
		return 0, 0, fmt.Errorf("negative")
	}
	mult, ok := lookup(suffix)
	if !ok {
		return 0, 0, fmt.Errorf("unknown unit %q", suffix)
	}
	return v, mult, nil
}

// String renders a Rate in the largest unit that keeps it readable, the inverse
// of ParseRate for every value ParseRate produces from a whole-unit input.
func (r Rate) String() string {
	switch {
	case r == 0:
		return "unlimited"
	case r >= Gbit && r%Gbit == 0:
		return fmt.Sprintf("%dGbit", r/Gbit)
	case r >= Mbit:
		return fmt.Sprintf("%gMbit", float64(r)/float64(Mbit))
	case r >= Kbit:
		return fmt.Sprintf("%gkbit", float64(r)/float64(Kbit))
	default:
		return fmt.Sprintf("%dbit", uint64(r))
	}
}

// String renders a Bytes count in decimal units, the inverse of ParseBytes.
func (b Bytes) String() string {
	switch {
	case b == 0:
		return "unlimited"
	case b >= TB:
		return fmt.Sprintf("%gTB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%gGB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%gMB", float64(b)/float64(MB))
	default:
		return fmt.Sprintf("%dB", uint64(b))
	}
}

// Limits is what a node's operator declares it is WILLING to serve (issue #143):
// a speed cap and a monthly traffic quota. It is the operator's statement about
// their own uplink and their own ISP contract — facts no measurement could ever
// discover, since no probe can read a data cap off a bill.
//
// Every field's zero value means "no limit", so the zero Limits is a node with no
// declared limits at all: exactly today's behaviour, which is what keeps #143
// opt-in and the existing datacenter fleet byte-for-byte unaffected.
//
// Limits is self-reported and that is safe — see the package doc's trust
// asymmetry. Over-declaring is inert (the measured term of min(declared,measured)
// binds); under-declaring only reduces what the node is given, which is the
// operator's prerogative and the entire point of the card.
type Limits struct {
	// SpeedCap is the aggregate bits/s across all of this node's sessions that the
	// operator is willing to carry. Aggregate, not per-session: an operator caps
	// what leaves their house, not what any one stranger gets. Zero = uncapped.
	SpeedCap Rate

	// MonthlyQuota is the bytes per billing cycle the operator is willing to spend
	// — their ISP's data cap, or whatever slice of it they choose to donate. Zero =
	// unlimited.
	//
	// Counted the way an ISP counts: a forwarded byte costs TWO, because it arrives
	// and then leaves (see LinkCrossings). So this is a budget in *metered* bytes,
	// not in bytes delivered to users: declaring 400GB serves roughly 200GB of
	// traffic and spends 400GB of the operator's cap. That is the number the
	// operator's bill is written in, which is why it is the number the flag takes —
	// but it means "the slice you choose to donate" is a slice of your CAP, not of
	// your throughput, and the two differ by 2x.
	MonthlyQuota Bytes

	// CycleDay is the day of the month the quota resets: the operator's BILLING
	// day, not the 1st.
	//
	// This field looks like a nicety and is not. Residential data caps reset on the
	// day the customer signed up, which is uniform-ish over 1..28. Hard-coding the
	// 1st would silently overshoot the real cap for ~27 of 28 operators — the node
	// would sail past its ISP's reset in the middle of the ISP's cycle and the
	// operator would eat exactly the overage bill this card exists to prevent. A
	// quota anchored to the wrong day is not a conservative approximation of a
	// quota; it is a broken one.
	//
	// Valid range is 1..28 — 28 so the anchor exists in February, rather than
	// having a 29th-of-the-month operator silently skip a reset. Zero means the
	// 1st, which is only correct when MonthlyQuota is unset anyway.
	CycleDay int
}

// Validate reports whether the declared limits are self-consistent, so cmd/node
// fails loudly at startup rather than a node registering with a quota that can
// never reset.
func (l Limits) Validate() error {
	if l.CycleDay < 0 || l.CycleDay > 28 {
		return fmt.Errorf("quota cycle day %d out of range (1..28; 28 so the anchor exists in February)", l.CycleDay)
	}
	if l.CycleDay > 0 && l.MonthlyQuota == 0 {
		return fmt.Errorf("quota cycle day %d set without a quota — the reset day is meaningless with no quota to reset", l.CycleDay)
	}
	return nil
}

// String renders the declared limits for a startup log line, so an operator can
// see at a glance that the node understood their flags the way they meant them.
func (l Limits) String() string {
	if l.SpeedCap == 0 && l.MonthlyQuota == 0 {
		return "no declared limits (uncapped, unmetered)"
	}
	day := l.CycleDay
	if day == 0 {
		day = 1
	}
	return fmt.Sprintf("speed cap %s, quota %s per cycle (resets day %d)", l.SpeedCap, l.MonthlyQuota, day)
}
