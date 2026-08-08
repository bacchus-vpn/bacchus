package selection

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
)

// NetworkKey returns a stable, opaque fingerprint of the network the device is
// attached to right now — the key under which a winning path is remembered
// (old #15, "learn per-network"). Its contract:
//
//   - STABLE per network: two connects on the same operator/network return the
//     SAME key, so the learned winner is reused instead of re-raced.
//   - DISTINCT across networks: a different network returns a DIFFERENT key, so a
//     stale winner from a network that blocked us is not trusted on one that
//     doesn't.
//   - NOT user-identifying: the result is written to disk, so it must be safe if
//     the file leaks — it fingerprints the *network*, never the person, and is a
//     hash, so no raw address is stored.
//
// It fingerprints the set of local subnets: for every up, non-loopback interface
// it takes each assigned address's *network* — the IP masked to its prefix, so
// the host part (which DHCP may change within the same network) does not affect
// the key — pairs it with the interface name, and hashes the sorted set. Masking
// to the network and hashing means no host IP or MAC is stored, only a digest of
// "which subnets this machine sits on", which is stable while attached and
// differs across most networks.
//
// Subnet + interface alone collide when two distinct networks share the same
// private subnet and adapter (e.g. two cafés both on 192.168.1.0/24 over Wi-Fi):
// one learning bucket for both, so a path that a censor blocked on one is tried
// first on the other. To break that, NetworkKey also mixes in a per-platform
// fingerprint of the DEFAULT GATEWAY — its MAC where a cheap ARP/neighbour lookup
// is available (Windows; see gatewayFingerprint) — which identifies the access
// point, not the user, and differs between the two cafés even when their subnets
// match (old #77). It is mixed into the same hash, so still no raw MAC is
// stored. Where the lookup isn't available (other platforms, or no resolvable
// gateway) gatewayFingerprint returns "" and the key is exactly the subnet+iface
// digest as before — the collision is merely not broken, never a regression, and
// a mis-keyed winner still just fails sustained-flow validation and the ladder
// falls through. With no usable interface (offline) it returns the degenerate
// "default" bucket, which disables per-network distinction but is still correct.
func NetworkKey() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "default"
	}
	var subnets []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			// Skip loopback and link-local (169.254/16, fe80::/10): they are not
			// network identifiers, and link-local can be derived from the MAC,
			// which we deliberately do not fingerprint.
			if ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLinkLocalMulticast() {
				continue
			}
			network := net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask}
			subnets = append(subnets, ifi.Name+" "+network.String())
		}
	}
	return networkKeyFrom(subnets, gatewayFingerprint())
}

// networkKeyFrom hashes the set of "iface network" descriptors, plus the
// gateway fingerprint when one is available, into the on-disk key. It is pure —
// dedup, sort, hash — so the fingerprint policy is testable without real
// interfaces. An empty subnet set yields the degenerate "default" bucket
// regardless of gw (offline means there is no meaningful gateway anyway).
//
// The gateway segment is appended, domain-separated, ONLY when gw is non-empty:
// an empty gw reproduces the exact digest from before old #77, so a device whose platform
// has no gateway lookup keeps its already-learned buckets rather than having
// them silently invalidated on upgrade.
func networkKeyFrom(subnets []string, gw string) string {
	if len(subnets) == 0 {
		return "default"
	}
	seen := make(map[string]bool, len(subnets))
	uniq := make([]string, 0, len(subnets))
	for _, s := range subnets {
		if !seen[s] {
			seen[s] = true
			uniq = append(uniq, s)
		}
	}
	sort.Strings(uniq)
	// Domain-separate the digest so it can't collide with any other hash of the
	// same material used elsewhere.
	material := "bacchus-netkey\x00" + strings.Join(uniq, "\n")
	if gw != "" {
		material += "\x00gw\x00" + gw
	}
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])[:16]
}
