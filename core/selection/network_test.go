package selection

import "testing"

// TestNetworkKeyFrom pins the fingerprint policy: an empty set is the degenerate
// bucket; a non-empty set hashes to a short, stable, order- and
// duplicate-independent digest; distinct subnet sets give distinct keys.
func TestNetworkKeyFrom(t *testing.T) {
	if got := networkKeyFrom(nil, ""); got != "default" {
		t.Fatalf("empty set = %q, want %q", got, "default")
	}
	// An empty subnet set is "default" regardless of a gateway fingerprint —
	// offline means there is no meaningful gateway to distinguish anything.
	if got := networkKeyFrom(nil, "aabbccddeeff"); got != "default" {
		t.Fatalf("empty set with gw = %q, want %q", got, "default")
	}

	a := networkKeyFrom([]string{"Wi-Fi 192.168.1.0/24"}, "")
	if len(a) != 16 {
		t.Fatalf("key length = %d, want 16 hex chars: %q", len(a), a)
	}
	if b := networkKeyFrom([]string{"Wi-Fi 192.168.1.0/24"}, ""); a != b {
		t.Fatalf("not stable across calls: %q vs %q", a, b)
	}

	// Order and duplicates must not change the key (same network set).
	s1 := networkKeyFrom([]string{"eth0 10.0.0.0/8", "Wi-Fi 192.168.1.0/24"}, "")
	s2 := networkKeyFrom([]string{"Wi-Fi 192.168.1.0/24", "eth0 10.0.0.0/8", "Wi-Fi 192.168.1.0/24"}, "")
	if s1 != s2 {
		t.Fatalf("order/dedup changed the key: %q vs %q", s1, s2)
	}

	// Different networks must fingerprint differently, or a stale winner leaks
	// across networks.
	if networkKeyFrom([]string{"Wi-Fi 192.168.1.0/24"}, "") == networkKeyFrom([]string{"Wi-Fi 10.0.0.0/8"}, "") {
		t.Fatal("different subnets must produce different keys")
	}
}

// TestNetworkKeyFromBackwardCompatible pins the exact digest for the no-gateway
// path. It must never change silently: it is the on-disk key every device
// without a gateway lookup (and every build predating old #77) already learned under, and
// changing the hashing would invalidate all of those buckets at once.
func TestNetworkKeyFromBackwardCompatible(t *testing.T) {
	const wantNoGW = "fa7d497429cba980"
	if got := networkKeyFrom([]string{"Wi-Fi 192.168.1.0/24"}, ""); got != wantNoGW {
		t.Fatalf("no-gw digest = %q, want %q (a change here silently resets every learned store)", got, wantNoGW)
	}
	const wantWithGW = "b0386080db283ddd"
	if got := networkKeyFrom([]string{"Wi-Fi 192.168.1.0/24"}, "aabbccddeeff"); got != wantWithGW {
		t.Fatalf("with-gw digest = %q, want %q", got, wantWithGW)
	}
}

// TestNetworkKeyFromGateway pins the old #77 hardening: mixing in a gateway
// fingerprint breaks the same-subnet collision (two networks that share a subnet
// but sit behind different access points get different keys), stays stable for a
// given gateway, and — crucially — leaves the no-gateway key untouched so the
// fallback path is a strict superset, never a regression.
func TestNetworkKeyFromGateway(t *testing.T) {
	subnet := []string{"Wi-Fi 192.168.1.0/24"}

	// Two cafés, same subnet+adapter, different gateway MAC: the collision the
	// old key had — now broken.
	cafeA := networkKeyFrom(subnet, "aabbccddeeff")
	cafeB := networkKeyFrom(subnet, "112233445566")
	if cafeA == cafeB {
		t.Fatal("same subnet behind different gateways must produce different keys (old #77)")
	}

	// Stable for a given gateway.
	if again := networkKeyFrom(subnet, "aabbccddeeff"); again != cafeA {
		t.Fatalf("same subnet+gateway not stable: %q vs %q", cafeA, again)
	}

	// Adding a gateway changes the key vs. the no-gateway digest (expected: it's
	// strictly more information), but the no-gateway digest itself is unchanged
	// by the existence of the gateway path.
	noGW := networkKeyFrom(subnet, "")
	if cafeA == noGW {
		t.Fatal("a resolved gateway must distinguish the key from the no-gateway digest")
	}

	// The gateway is not the only discriminator: a different subnet with the
	// same gateway is still a different network.
	if networkKeyFrom(subnet, "aabbccddeeff") == networkKeyFrom([]string{"Wi-Fi 10.0.0.0/8"}, "aabbccddeeff") {
		t.Fatal("different subnets behind the same gateway must still differ")
	}
}

// TestNetworkKeyLive checks the real fingerprint is well-formed and deterministic
// on whatever interfaces the host has (its value is environment-dependent).
func TestNetworkKeyLive(t *testing.T) {
	k1 := NetworkKey()
	if k1 != NetworkKey() {
		t.Fatal("NetworkKey must be deterministic within a run")
	}
	if k1 != "default" && len(k1) != 16 {
		t.Fatalf("NetworkKey = %q, want \"default\" or 16 hex chars", k1)
	}
}
