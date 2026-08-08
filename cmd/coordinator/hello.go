package main

import (
	"log"
	"time"
)

// A rejected `hello` is the cheapest thing any source on the internet can make
// this coordinator do (issue #217).
//
// Nothing gates handle() before its switch — admission is checked per message
// type inside it, and "hello" deliberately predates role logic (issue #8,
// ADR-0016) — and the raw-JSON path on the signaling port is open by design
// (ADR-0059 slice 1, kept by ADR-0062 so a client predating the shaped hop still
// works). So an unauthenticated datagram from a source that may be spoofed drove
// one log line, per datagram, naming that source. Issue #213's whole argument
// rests on the rule that breaks: **one log line per spoofed datagram is how a log
// becomes as good as no log.** challengeStore's at-capacity latch,
// rendezvousMux.stunWriteFailed and coordLink.noteOnce are all built to avoid
// exactly this; this line was not.
//
// # What is bounded, and what deliberately is not
//
// The LOG is bounded here. The REPLY is not, and that is a ruling rather than an
// omission — see the reply's own note in handle()'s "hello" case.
//
// # Why the source address is not named
//
// It is unauthenticated and trivially spoofable, so under the flood this bound
// exists for, every address printed is the attacker's choice: the field that
// looks like the diagnosis is the field being forged. The same reasoning is
// written out at rendezvousMux.stunWriteFailed.
//
// Nothing is lost by omitting it, because a real peer's identity is on record in
// two places this line was never the best of. The peer logs its own side —
// core/engine.go's reject case emits "coordinator rejected us: <reason>" — and a
// node that gets past hello and is then fenced on its release is logged by the
// register handler WITH its node id and source ("register %s (%s): fenced").
//
// # Why the reason is not the key
//
// The obvious refinement — one line per distinct reason, so three protocol
// failures produce three lines — is a memory-growth vector here.
// handshake.Check's version reasons embed the PEER's version number, an integer
// the sender chooses, so a map keyed by reason string is a table an attacker
// sets the size of with one datagram per entry. The bound is therefore on the
// rate, not on the variety, and the reason travels as the line's payload rather
// than as its key.
const helloRejectLogInterval = time.Minute

var (
	// helloRejectLogged is when the last hello-rejection line was written, and
	// helloRejectSuppressed counts the rejections since. Both are ordinary
	// package variables rather than an atomic or a mutex-guarded struct because
	// noteHelloReject is only ever called from handle(), which holds mu for its
	// whole body — the same lock the registry itself lives under.
	helloRejectLogged     time.Time
	helloRejectSuppressed int
)

// noteHelloReject logs a rejected hello at most once per helloRejectLogInterval,
// carrying a count of what was suppressed since the previous line.
//
// The count is reported on the NEXT line that is allowed through, so a burst that
// stops has its tail counted only when the next rejection arrives. That is
// accepted: this is a bound on the log, not an accounting of the traffic, and
// a goroutine ticking purely to flush a counter would be more machinery than the
// fact is worth.
//
// now comes from handle(), which already has it, so a test can drive the interval
// without sleeping through it.
func noteHelloReject(now time.Time, reason string) {
	if !helloRejectLogged.IsZero() && now.Sub(helloRejectLogged) < helloRejectLogInterval {
		helloRejectSuppressed++
		return
	}
	suppressed := helloRejectSuppressed
	helloRejectLogged, helloRejectSuppressed = now, 0
	if suppressed == 0 {
		log.Printf("hello rejected (%s)", reason)
		return
	}
	log.Printf("hello rejected (%s); %d further rejection(s) since the previous such line were not logged individually (issue #217)",
		reason, suppressed)
}
