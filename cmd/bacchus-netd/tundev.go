//go:build linux

// Creating the TUN device, and handing its descriptor across the privilege
// boundary.
//
// ADR-0049 §5 is the argument that chose a unix socket over the alternatives:
// tun2socks.go bridges the device to the gVisor netstack IN THE CLIENT PROCESS,
// so the privileged side must create the device and the unprivileged side must
// read and write it. A socket is the only one of the three candidate designs
// that can pass a file descriptor at all.
//
// # Two corrections to §5's mechanism, both found by running it
//
// The record names CreateTUN (tun_linux.go:551) as the privileged half and
// CreateTUNFromFile (tun_linux.go:585) as "only unprivileged work on a
// descriptor it is handed". The split is in the right place; the second half of
// that sentence is not quite true, and the difference matters:
//
//  1. CreateTUNFromFile ends by calling setMTU, which is an SIOCSIFMTU ioctl and
//     needs CAP_NET_ADMIN. Handed a descriptor, an unprivileged client gets
//     "failed to set MTU of TUN device: operation not permitted" and no device.
//     The entry point that really is unprivileged is CreateUnmonitoredTUNFromFD:
//     it does TUNGETIFF and TUNSETOFFLOAD on the fd it was given and nothing
//     else. What it gives up is the netlink link-event listener behind
//     Device.Events(), which nothing in this repo calls — tun2socks.go uses
//     MTU, BatchSize, Read, Write and Close. So the helper sets the MTU itself,
//     which it was always better placed to do, and the client wraps the
//     descriptor with no capability at all.
//
//  2. The device must NOT be created with IFF_VNET_HDR. CreateTUN sets it, and
//     with it set wireguard-go's Write requires an offset of at least
//     virtioNetHdrLen to prepend the virtio header. tun2socks.go's pumpOutbound
//     calls dev.Write(bufs, 0) — correct for wintun, which has no such header —
//     and on a vnet-hdr device that returns "invalid offset" for every packet.
//     Creating the device without the flag makes the Linux Device honour offset
//     0 exactly as the Windows one does, so the portable pump is portable
//     without changes. The cost is GSO/GRO batching (BatchSize drops from 128
//     to 1), which this architecture cannot use anyway: every flow is
//     terminated in the netstack and re-dialled over SOCKS, so nothing large
//     passes through end to end.
//
// Neither is a decision — §5's reasoning, its choice of socket and its refusal
// to fork the dependency all stand. They are the mechanism details that make
// that reasoning work, which is why they are recorded here rather than in an
// ADR.
package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const (
	// tunName is fixed and chosen HERE. ADR-0049 §3.5: interfaces are derived,
	// never named by the client. There is one tunnel per running client, so
	// there is nothing to allocate.
	tunName = "bacchus0"

	// tunMTU matches the netstack's own fallback in tun2socks.go.
	tunMTU = 1420
)

// createTUN opens /dev/net/tun, binds it to our interface name, and sets the
// MTU. Returns the descriptor to pass to the client, plus the interface index
// the kill-switch and the routes need.
//
// The privileged surface here is exactly two syscalls wide: the open and the
// TUNSETIFF. Everything the client then does with the descriptor is
// unprivileged.
func createTUN(nl *netlinkPool) (fd int, ifIndex int, err error) {
	fd, err = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()

	ifr, err := unix.NewIfreq(tunName)
	if err != nil {
		return -1, 0, err
	}
	// IFF_NO_PI: no packet-information prefix, so what is read and written is a
	// bare IP packet — which is what the netstack expects to inject.
	// Deliberately no IFF_VNET_HDR: see the package doc above.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return -1, 0, fmt.Errorf("TUNSETIFF %s: %w", tunName, err)
	}

	iface, err := net.InterfaceByName(tunName)
	if err != nil {
		return -1, 0, fmt.Errorf("find %s after creating it: %w", tunName, err)
	}
	ifIndex = iface.Index

	if err = nl.do(func(c *nlConn) error { return c.setLinkMTU(ifIndex, tunMTU) }); err != nil {
		return -1, 0, fmt.Errorf("set MTU on %s: %w", tunName, err)
	}
	return fd, ifIndex, nil
}

// Note there is deliberately no "is the TUN still there?" check. A TUN created
// this way is owned by its descriptors, so it disappears when the last holder
// closes one — including when the client is killed. There is no persistent
// device to reap, which is the property ADR-0049 §5 chose this shape for over a
// persistent uid-owned device.

// closeFD is the cleanup path when a descriptor was created but could not be
// handed over. Without it a failed handover leaves the device up with nothing
// reading it.
func closeFD(fd int) {
	if fd >= 0 {
		unix.Close(fd)
	}
}
