package coldstart

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
)

// SecretStore resolves a hex secret ID (the STUN USERNAME on the wire) to
// the per-user secret an operator issued it, so [Serve] can check
// MESSAGE-INTEGRITY. Implementations must be safe for concurrent use.
type SecretStore interface {
	Lookup(secretID string) (secret []byte, ok bool)
}

// MemStore is a SecretStore backed by an in-memory map.
type MemStore struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

// NewMemStore builds an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{secrets: map[string][]byte{}} }

// Add registers secretID -> secret, overwriting any prior value.
func (s *MemStore) Add(secretID string, secret []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[secretID] = secret
}

// Lookup implements [SecretStore].
func (s *MemStore) Lookup(secretID string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.secrets[secretID]
	return v, ok
}

// secretFile is the on-disk JSON form: {"<hex secretID>": "<hex secret>"}.
type secretFile map[string]string

// LoadMemStore reads a secrets file written by [MemStore.SaveFile] (or by
// cmd/coldstart-issue) into a fresh MemStore. The file is operator-managed
// out-of-band provisioning (design doc §4.2.2/§7.3) — there is no vouch/trust
// system wired in yet (issue #18's follow-on work), so every entry here is
// trusted equally.
func LoadMemStore(path string) (*MemStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("coldstart: read secrets file: %w", err)
	}
	var f secretFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("coldstart: parse secrets file: %w", err)
	}
	store := NewMemStore()
	for id, hexSecret := range f {
		secret, err := hex.DecodeString(hexSecret)
		if err != nil {
			return nil, fmt.Errorf("coldstart: secrets file: bad secret for %s: %w", id, err)
		}
		store.Add(id, secret)
	}
	return store, nil
}

// SaveFile writes s to path in the format [LoadMemStore] reads, so an
// operator-side tool can append a freshly issued secret and persist it.
//
// The write is ATOMIC — a complete file is renamed over the target and the live
// file is never opened for writing (issue #178) — because the only writer,
// cmd/coldstart-issue, is read-modify-write over the whole store. A torn write
// there does not lose the entry being added; it destroys every bootstrap secret
// ever issued, none of which is reconstructible. [writeFileAtomic] carries that
// argument in full, along with the three ways the result differs from the
// os.WriteFile this used to be.
//
// It does not create path's parent directory, which is unchanged: a missing
// secrets directory is still an error rather than something a mint conjures.
//
// The lock that stops two concurrent issuers dropping one another's entry is
// cmd/coldstart-issue's, not this — a whole file is what a READER is promised,
// and a store that never held the loser's secret marshals to a perfectly
// well-formed one.
func (s *MemStore) SaveFile(path string) error {
	s.mu.RLock()
	f := make(secretFile, len(s.secrets))
	for id, secret := range s.secrets {
		f[id] = hex.EncodeToString(secret)
	}
	s.mu.RUnlock()
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("coldstart: marshal secrets file: %w", err)
	}
	if err := writeFileAtomic(path, b); err != nil {
		return fmt.Errorf("coldstart: write secrets file: %w", err)
	}
	return nil
}

// Serve answers STUN-shaped bootstrap requests on pc until ctx is done or
// pc.ReadFrom returns an error. snapshotFn is called once per authenticated
// request to fetch the current signed snapshot (the caller — cmd/coordinator
// — owns building and periodically re-signing it from the live registry).
//
// Every well-formed Binding Request gets a plain Binding Success Response
// with the reflexive address, whether or not it authenticates — an
// unauthenticated or malformed-credential request is answered exactly as a
// public STUN server would answer it (design principle #4: no proxy-shaped
// response leaks to a prober without the secret). Only a request whose
// MESSAGE-INTEGRITY validates against a known secret gets the snapshot
// attribute appended to that same response.
func Serve(ctx context.Context, pc net.PacketConn, secrets SecretStore, snapshotFn func() []byte) error {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		raw := append([]byte(nil), buf[:n]...)
		var reflexive netip.AddrPort
		if ua, ok := src.(*net.UDPAddr); ok {
			reflexive = ua.AddrPort()
		}
		resp, ok := handleRequest(raw, reflexive, secrets, snapshotFn)
		if !ok {
			continue
		}
		_, _ = pc.WriteTo(resp, src)
	}
}

// handleRequest is the pure per-packet logic behind [Serve], split out so it
// can be unit-tested without a live socket. reflexive is the request's
// observed source address, echoed back exactly like a real STUN server
// would (this is the one piece of the response that must vary per source —
// everything else about the response shape is identical whether or not the
// request authenticates).
func handleRequest(raw []byte, reflexive netip.AddrPort, secrets SecretStore, snapshotFn func() []byte) ([]byte, bool) {
	m, err := parse(raw)
	if err != nil || m.typ != typeBindingRequest {
		return nil, false
	}

	var snapshot []byte
	if usernameVal, ok := m.get(attrUsername); ok {
		secretID := string(usernameVal)
		if secret, ok := secrets.Lookup(secretID); ok {
			if off := messageIntegrityOffset(raw); off >= 0 && verifyMessageIntegrity(raw, off, secret) {
				snapshot = snapshotFn()
			}
		}
	}

	return buildResponse(m.tx, reflexive, snapshot), true
}
