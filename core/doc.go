// Package core is the shared Bacchus engine: a single node that can act as any
// combination of client, relay, and exit. The product binaries (cmd/node,
// clients/*) and the mobile facade (bind/) are thin wrappers around it.
//
// The engine holds no package-level mutable state — every value hangs off an
// [Engine], constructed with [New] from a [Config]. That is what lets it be
// embedded directly (desktop) and bound via gomobile (mobile), and lets several
// engines coexist in one process (tests, multi-role fixtures).
//
// Lifecycle:
//
//	eng, err := core.New(cfg)   // validate config, build the transport
//	err = eng.Start(ctx)        // dial the coordinator, bring up forwarder roles
//	// client role only:
//	exits, err := eng.ListExits(ctx, timeout)
//	err = eng.Connect(ctx)      // direct-first, relay-fallback; local SOCKS5
//	eng.Wait()                  // block until Stop() or ctx cancellation
//	eng.Stop()                  // tear everything down (idempotent)
//
// Status is surfaced through [Config.OnEvent]; when it is nil the engine logs
// the same messages via the standard logger.
//
// The network layer sits behind [Transport]: it establishes authenticated,
// bidirectional byte-stream [Session]s between two paired peers, over which the
// role code opens labeled [Stream]s. WebRTC (pion) is the first implementation;
// others (obfuscated UDP, Reality-XHTTP) implement the same interface and slot
// into a client-side pool (ADR-0008). The engine drives each handshake through a
// [Signaler] it backs with the coordinator connection, so nothing above the
// interface knows which transport carries a session.
//
// Above the transport, traffic is encrypted end-to-end from client to exit with
// Noise_NK (see e2e.go): the exit's static public key is its node id, so the
// client authenticates the exit it selected, and a relay in the path forwards
// ciphertext and the next hop only — never the destination or content
// (ADR-0009). The exit terminates this channel identically whether it was
// reached directly or through a relay.
package core
