// Package selection is the pure, side-effect-free core of the client's
// connection strategy (old #15): given the exits a coordinator advertised, the
// transports this build carries, and what worked here before, it decides the
// order in which candidate paths are tried and remembers the winner so it is
// tried first next time.
//
// No single path reaches an exit for every user. Russian blocking is
// per-operator, regionally fragmented, and time-varying, so coverage is the
// union of many partial paths and the right one is discovered per user, per
// network, per moment. A path is a [Candidate]: a transport (webrtc, reality, …),
// a specific exit, and a mode (direct hole-punch or relayed through nodes).
//
// The strategy is a priority ladder ([Ladder]): stay on the fast direct path —
// the primary transport to the lowest-ping exit in the user's chosen geo —
// exhausting exits before switching protocol, and switching protocol before
// routing through nodes. A [Store] remembers each validated success on this
// device, keyed to the network and geo, so the learned winner short-circuits the
// ladder on the next connect and can be reset by the user.
//
// This package holds every ordering and learning decision but performs no I/O
// beyond the on-device store and touches no network — the engine (core/pool.go)
// drives dialing, sustained-flow validation, and racing on top of it. Keeping
// the policy here makes it unit-testable without a coordinator, an exit, or a
// clock.
package selection
