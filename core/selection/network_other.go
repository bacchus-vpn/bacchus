//go:build !windows

package selection

// gatewayFingerprint returns "" on platforms without a cheap default-gateway MAC
// lookup, so NetworkKey falls back to the subnet+interface digest unchanged
// (old #77). Only Windows has an implementation today (network_windows.go);
// the exit/relay/coordinator roles that run on Linux don't learn per-network
// paths — the transport pool is a client-side concern — so none is needed there
// yet. A future platform can add its own build-tagged file without touching the
// pure networkKeyFrom policy.
func gatewayFingerprint() string { return "" }
