//go:build windows

package selection

import (
	"encoding/hex"
	"net"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// gatewayFingerprint returns a stable, non-user-identifying token for the
// network's default gateway on Windows — the gateway's MAC, resolved via ARP and
// hex-encoded (issue #77). The gateway MAC identifies the access point / router
// that everyone on the network shares, never the user's own device, and it is
// only ever mixed into NetworkKey's hash, so it is never persisted raw. It is
// what lets NetworkKey tell apart two different networks that happen to share the
// same private subnet and adapter (two cafés both on 192.168.1.0/24 over Wi-Fi).
//
// Best-effort and fail-open: any failure — no default gateway, an ARP miss, an
// API error — returns "", and NetworkKey falls back to its subnet+interface
// digest with no gateway segment. It costs one GetAdaptersAddresses call plus one
// SendARP per connect/reselect, both served from the ARP cache the machine
// already warmed talking to its gateway, so it is cheap.
func gatewayFingerprint() string {
	ip := defaultGatewayIP()
	if ip == nil {
		return ""
	}
	mac := arpLookup(ip)
	if len(mac) == 0 {
		return ""
	}
	return hex.EncodeToString(mac)
}

// gaaFlags asks GetAdaptersAddresses for gateways while skipping the unicast /
// anycast / multicast / DNS sub-lists we never read, keeping the returned buffer
// small.
const gaaFlags = windows.GAA_FLAG_INCLUDE_GATEWAYS |
	windows.GAA_FLAG_SKIP_UNICAST |
	windows.GAA_FLAG_SKIP_ANYCAST |
	windows.GAA_FLAG_SKIP_MULTICAST |
	windows.GAA_FLAG_SKIP_DNS_SERVER

// defaultGatewayIP returns the IPv4 default-gateway address of the up,
// non-loopback adapter with the lowest IPv4 route metric — i.e. the one carrying
// the actual default route — or nil if none is found. The whole adapter-list
// walk happens while the backing buffer is alive (runtime.KeepAlive), and the
// chosen address is copied out of it, because SocketAddress.IP aliases that
// buffer.
func defaultGatewayIP() net.IP {
	size := uint32(15000) // typical first-call size; grown on overflow
	var buf []byte
	for attempt := 0; ; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET, gaaFlags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		// ERROR_BUFFER_OVERFLOW writes the needed size back into `size`; retry
		// once or twice with the larger buffer, then give up (fail-open).
		if err != windows.ERROR_BUFFER_OVERFLOW || attempt >= 3 {
			return nil
		}
	}

	var best net.IP
	var bestMetric uint32
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp || aa.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		var gwIP net.IP
		for gw := aa.FirstGatewayAddress; gw != nil; gw = gw.Next {
			if ip := gw.Address.IP(); ip != nil {
				if v4 := ip.To4(); v4 != nil {
					gwIP = append(net.IP(nil), v4...) // copy out of buf before it's reused/freed
					break
				}
			}
		}
		if gwIP == nil {
			continue
		}
		if best == nil || aa.Ipv4Metric < bestMetric {
			best, bestMetric = gwIP, aa.Ipv4Metric
		}
	}
	runtime.KeepAlive(buf)
	return best
}

var (
	iphlpapi    = windows.NewLazySystemDLL("iphlpapi.dll")
	procSendARP = iphlpapi.NewProc("SendARP")
)

// arpLookup resolves ip's link-layer (MAC) address with SendARP, which answers
// from the local ARP cache — warm, since the machine just talked to its gateway
// — or sends a resolution request on a miss. Returns nil on any failure. Only
// the hardware address bytes are returned; nothing is stored.
func arpLookup(ip net.IP) []byte {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	// SendARP's destination is an IPAddr (ULONG in network byte order), i.e. the
	// four octets a.b.c.d laid out in memory as [a][b][c][d] — the value
	// inet_addr would return. On a little-endian host that is exactly this
	// composition.
	dst := uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
	var mac [8]byte // Ethernet is 6; SendARP wants room and reports the real length
	macLen := uint32(len(mac))
	ret, _, _ := procSendARP.Call(
		uintptr(dst),
		0, // SrcIP 0: let the stack pick the source
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret != 0 || macLen == 0 || macLen > uint32(len(mac)) {
		return nil // NO_ERROR is 0; anything else (incl. a stale/absent entry) fails open
	}
	return append([]byte(nil), mac[:macLen]...)
}
