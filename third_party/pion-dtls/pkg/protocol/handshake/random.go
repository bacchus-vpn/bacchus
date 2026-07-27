// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Consts for Random in Handshake.
const (
	RandomBytesLength = 28
	RandomLength      = RandomBytesLength + 4
)

// Random value that is used in ClientHello and ServerHello
//
// https://tools.ietf.org/html/rfc4346#section-7.4.1.2
type Random struct {
	GMTUnixTime time.Time
	RandomBytes [RandomBytesLength]byte
}

// MarshalFixed encodes the Handshake.
func (r *Random) MarshalFixed() [RandomLength]byte {
	var out [RandomLength]byte

	binary.BigEndian.PutUint32(out[0:], uint32(r.GMTUnixTime.Unix())) //nolint:gosec // G115
	copy(out[4:], r.RandomBytes[:])

	return out
}

// UnmarshalFixed populates the message from encoded data.
func (r *Random) UnmarshalFixed(data [RandomLength]byte) {
	r.GMTUnixTime = time.Unix(int64(binary.BigEndian.Uint32(data[0:])), 0)
	copy(r.RandomBytes[:], data[4:])
}

// Populate fills the handshakeRandom with random values
// may be called multiple times.
//
// bacchus patch (issue #57): upstream set GMTUnixTime = time.Now(), and
// MarshalFixed wrote it verbatim into the wire value's first 4 bytes — a
// wall-clock-correlated tell modern browsers don't have (they fill all 32
// bytes randomly). This struct is pion's state.localRandom, hashed directly
// into the master-secret PRF (state.go), so the fix has to live here rather
// than in a post-hoc wire rewrite (see bacchus docs/adr/0018). GMTUnixTime now
// holds a uniformly random second count instead of the real time; the wire
// format and every caller are unchanged.
func (r *Random) Populate() error {
	tmp := make([]byte, RandomLength)
	if _, err := rand.Read(tmp); err != nil {
		return err
	}

	r.GMTUnixTime = time.Unix(int64(binary.BigEndian.Uint32(tmp[0:4])), 0)
	copy(r.RandomBytes[:], tmp[4:])

	return nil
}
