package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// Mesh-walk recovery wiring (issue #31, design §4.3). Two independent halves:
//
//   - startCourier makes a relay/exit node a COURIER: it keeps a fresh
//     coordinator-signed snapshot cached and serves it to recovering clients that
//     can no longer reach any coordinator. It is a dispenser of the coordinator's
//     signed bytes, never an author.
//   - meshRecovery is the client half: the peers/proof/key a client walks when
//     every coordinator is unreachable, consumed by run's recovery loop.
//
// The two never share a process requirement — a pure client carries no courier, a
// pure relay carries no recovery config — so each is optional and self-contained.

// courierRefresh is how often a courier re-fetches its snapshot from the
// coordinator. Well under the coordinator's snapshot TTL, so the cache a courier
// hands out is never more than one interval stale while its coordinator is up.
const courierRefresh = 30 * time.Second

// startCourier brings up the mesh-walk courier on listen: it binds the UDP socket,
// starts serving cached snapshots gated on the invite's coordinator key, and starts
// a background loop that refreshes the cache from that coordinator. It returns once
// the socket is bound (so a bind failure surfaces to main), with serving and
// refreshing running in the background until ctx is done.
//
// The courier authenticates its own fetches to the coordinator with the invite's
// per-user secret — exactly as a client cold-start does — so no new coordinator
// path is needed to feed it; it reuses coldstart.Bootstrap. It hands out that
// snapshot only to a client presenting proof of prior contact (ServeCourier), so a
// courier is not an open directory oracle.
func startCourier(ctx context.Context, listen, inviteStr string) error {
	if inviteStr == "" {
		return errors.New("-courier-listen requires -courier-invite (how the courier fetches the snapshot it serves)")
	}
	inv, err := coldstart.DecodeInvite(strings.TrimSpace(inviteStr))
	if err != nil {
		return fmt.Errorf("decode -courier-invite: %w", err)
	}
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return fmt.Errorf("courier listen %s: %w", listen, err)
	}

	cache := coldstart.NewSnapshotCache()
	// Prime the cache once synchronously so a courier that comes up while its
	// coordinator is reachable can serve immediately; a failure here is non-fatal
	// (the refresh loop retries, and until then the courier just answers as a plain
	// STUN endpoint).
	if err := refreshCourier(ctx, inv, cache); err != nil {
		log.Printf("courier: initial snapshot fetch failed (will retry): %v", err)
	}

	go func() {
		if err := coldstart.ServeCourier(ctx, pc, inv.PublicKey, cache); err != nil && ctx.Err() == nil {
			log.Printf("courier: serve stopped: %v", err)
		}
	}()
	go courierRefreshLoop(ctx, inv, cache)
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	log.Printf("mesh-walk courier serving cached snapshots on %s (issue #31)", listen)
	return nil
}

// courierRefreshLoop re-fetches the courier's snapshot on courierRefresh until ctx
// is done. A failed fetch keeps the previous cache — a courier serving a slightly
// stale but genuine snapshot is the whole point when coordinators are flaky.
func courierRefreshLoop(ctx context.Context, inv coldstart.Invite, cache *coldstart.SnapshotCache) {
	t := time.NewTicker(courierRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := refreshCourier(ctx, inv, cache); err != nil {
				log.Printf("courier: snapshot refresh failed (serving previous): %v", err)
			}
		}
	}
}

// refreshCourier performs one authenticated bootstrap fetch and, on success, stores
// the signed bytes verbatim for the courier to hand out.
func refreshCourier(ctx context.Context, inv coldstart.Invite, cache *coldstart.SnapshotCache) error {
	fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := coldstart.Bootstrap(fetchCtx, inv.Coordinator, inv.SecretID, inv.Secret, inv.PublicKey)
	if err != nil {
		return err
	}
	cache.Store(res.Signed)
	return nil
}

// meshRecovery is a client's warm-recovery configuration: the peer couriers to ask,
// the proof of prior contact to present, and the coordinator key to verify replies
// against. nil means recovery is disabled — a client with no configured peers fails
// cold as before.
type meshRecovery struct {
	peers  []string
	proof  []byte
	pubkey ed25519.PublicKey
}

// loadMeshRecovery assembles the client recovery config from its flags, or returns
// nil when no peers are configured (recovery off). It fails loudly on a
// half-configured setup — peers without a proof or key would silently never
// recover — so a misconfiguration surfaces at startup, not during an outage.
func loadMeshRecovery(peersCSV, proofPath, pubkeyHex string) (*meshRecovery, error) {
	peers := splitCSV(peersCSV)
	if len(peers) == 0 {
		return nil, nil
	}
	if proofPath == "" || pubkeyHex == "" {
		return nil, errors.New("-mesh-peers requires -mesh-proof (a cached snapshot as proof of prior contact) and -mesh-pubkey (the coordinator snapshot key)")
	}
	pub, err := hex.DecodeString(strings.TrimSpace(pubkeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("-mesh-pubkey must be a %d-byte ed25519 public key in hex", ed25519.PublicKeySize)
	}
	proof, err := os.ReadFile(proofPath)
	if err != nil {
		return nil, fmt.Errorf("read -mesh-proof %s: %w", proofPath, err)
	}
	if len(proof) == 0 {
		return nil, fmt.Errorf("-mesh-proof %s is empty", proofPath)
	}
	return &meshRecovery{peers: peers, proof: proof, pubkey: ed25519.PublicKey(pub)}, nil
}

// maxMeshRecoveries bounds how many times one run() invocation will walk the mesh
// and reconnect before giving up, so a client can never spin forever chasing a
// directory whose coordinators are all gone.
const maxMeshRecoveries = 5

// runNode starts the engine against coords and keeps it running. A forwarder-only
// node registers and serves until interrupted; a client connects and, when every
// coordinator is unreachable and recovery is configured, walks the mesh for a fresh
// directory and reconnects through it — rebuilding the engine with the rediscovered
// coordinators. Recovery engages at BOTH boundaries (issue #115): at first connect,
// when Connect returns core.ErrNoCoordinatorReachable (direct or pooled); and
// mid-session, when the engine's own failover loop rediscovers a fresh directory and
// signals eng.NeedsRecovery. Both converge here on the same rebuild. It returns the
// first unrecoverable error, or nil once the node has run to interruption.
func runNode(ctx context.Context, cfg core.Config, coords []string, mesh *meshRecovery) error {
	proof := []byte(nil)
	if mesh != nil {
		proof = mesh.proof
	}
	for attempt := 0; ; attempt++ {
		cfg.Coordinators = coords
		// Plumb mesh recovery into the engine so its failover loops can trigger a walk
		// from inside a live session when every coordinator goes silent mid-session
		// (issue #115), not only at first connect. proof evolves across rebuilds: each
		// fresher snapshot becomes the next proof of prior contact.
		if mesh != nil {
			cfg.MeshPeers, cfg.MeshProof, cfg.MeshPubKey = mesh.peers, proof, mesh.pubkey
		}
		eng, err := core.New(cfg)
		if err != nil {
			return err
		}
		if err := eng.Start(ctx); err != nil {
			return err
		}
		if !eng.HasRole(core.RoleClient) {
			eng.Wait() // forwarder-only: serve until interrupted
			return nil
		}

		// The client half. On a node that ALSO serves, a client-connect failure is
		// retried against the live engine rather than returned, so the relay/exit roles
		// it donates survive its own consumer side wobbling instead of dying with it
		// (issue #12) — see clientHalf.run. meshOn tracks whether the mesh-walk rebuild
		// below is still available this pass, so once the recoveries are spent a serving
		// node falls back to retrying in place rather than to the fatal return.
		err = clientHalf{
			eng:     eng,
			serving: eng.HasRole(core.RoleRelay) || eng.HasRole(core.RoleExit),
			meshOn:  mesh != nil && attempt < maxMeshRecoveries,
			backoff: clientRetryBackoff,
		}.run(ctx)
		if errors.Is(err, errNodeStopped) {
			return nil
		}
		if err == nil {
			// Connected. Run until interrupted, or until a mid-session mesh-walk found a
			// fresh directory and asked to be rebuilt against it (issue #115).
			select {
			case <-eng.Done():
				return nil // engine stopped (interrupt / ctx cancellation)
			case <-eng.NeedsRecovery():
				fresh, freshProof := eng.RecoveredDirectory()
				// Stop the old engine first: it frees the SOCKS listener and drains its
				// goroutines, so the rebuild binds the same address cleanly with no
				// double-connect. The failover loop has already stopped itself.
				eng.Stop()
				if ctx.Err() != nil {
					return nil // shutting down concurrently with the signal — exit cleanly
				}
				coords, proof = fresh, freshProof
				attempt = 0 // a mid-session recovery follows a healthy session, not startup spin
				log.Printf("mesh-walk: mid-session rediscovery of %d coordinator(s) — reconnecting (issue #115)", len(fresh))
				continue
			}
		}
		// Initial connect failed. Only an all-coordinators-unreachable failure is
		// recoverable by mesh-walk, and only when the client was given peers to walk.
		// Anything else is a real failure to surface.
		if mesh == nil || !errors.Is(err, core.ErrNoCoordinatorReachable) || attempt >= maxMeshRecoveries {
			eng.Stop()
			return err
		}
		res, werr := eng.MeshWalk(ctx, mesh.peers, proof, mesh.pubkey)
		eng.Stop()
		if werr != nil {
			return fmt.Errorf("mesh-walk recovery: %w", werr)
		}
		fresh := res.Snapshot.AddrsForRole("coordinator")
		if len(fresh) == 0 {
			return errors.New("mesh-walk recovered a snapshot that lists no coordinators")
		}
		// Adopt the rediscovered coordinators and carry the fresher snapshot as the
		// next proof, then rebuild and reconnect.
		coords, proof = fresh, res.Signed
		log.Printf("mesh-walk: rediscovered %d coordinator(s) via a peer — reconnecting (issue #31)", len(fresh))
	}
}
