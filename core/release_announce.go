package core

// The announcement half of the signed release channel (issue #34, ADR-0052 §2,
// ADR-0065 §3).
//
// # There is nothing to build here, and that is the point
//
// A coordinator stamps its own release on every client reply and
// observeNetworkVersion already evaluates it on each one. Learning that a newer
// release exists therefore costs NO NEW TRAFFIC WHATSOEVER — it is a field on a
// message the peer was already going to send — which is what makes the
// anti-fingerprinting constraint on #34 tractable rather than a tension to be
// split.
//
// What was missing was a way for an embedder to READ it. The engine emits an
// "update available" event, and an event is a formatted sentence: a client that
// parsed one back into a version would be depending on a log line's wording. This
// file adds the accessor and nothing else.

// NetworkRelease returns the release the coordinator last advertised on a client
// reply, or "" when none has arrived yet.
//
// It is the exact string as received, not a parsed version, because a garbled
// advert must stay distinguishable from an absent one: observeNetworkVersion
// deliberately does not fail a client on either, and neither does this.
//
// # It is an ANNOUNCEMENT and not an authorization
//
// Nothing may be trusted on the strength of this value. A coordinator can announce
// a release that does not exist, or withhold one that does; what it cannot do is
// substitute a release, because the manifest a peer then fetches is signed by the
// offline root's update key and every artifact is named by its own digest. The
// most a lying coordinator achieves here is a wasted manifest fetch — and a
// manifest that does not verify is not a release.
//
// This is the same argument core/admission.CRL already makes about itself, and the
// reason "the coordinator must not be trusted with code" survives the coordinator
// being the thing that says a release exists: carrying is not authorizing.
func (e *Engine) NetworkRelease() string {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	return e.lastNetVersion
}
