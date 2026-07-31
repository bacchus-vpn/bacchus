//go:build linux

// File-descriptor passing over the control socket, and the peer-credential
// read that gates it. This is the half of the protocol that cannot be
// expressed as bytes in a frame, and it is the reason ADR-0049 §5 chose a unix
// socket over the two alternatives: a socket is the only one of the three that
// can pass a file descriptor at all.
package netdwire

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// SendReplyWithFD writes a reply frame and, in the same sendmsg, attaches fd as
// SCM_RIGHTS ancillary data.
//
// One sendmsg rather than "write the frame, then send the fd" on purpose: the
// two must not be separable. A reader that got the frame but not the descriptor
// would have a reply claiming a TUN exists and no way to reach it, and would
// have to invent a rule for how long to wait before deciding otherwise.
func SendReplyWithFD(c *net.UnixConn, rep *Reply, fd int) error {
	body, err := frameBytes(rep)
	if err != nil {
		return err
	}
	rights := unix.UnixRights(fd)
	n, oobn, err := c.WriteMsgUnix(body, rights, nil)
	if err != nil {
		return err
	}
	if n != len(body) || oobn != len(rights) {
		return fmt.Errorf("netdwire: short control write (%d/%d body, %d/%d rights)", n, len(body), oobn, len(rights))
	}
	return nil
}

// ReadReplyWithFD reads one reply that is expected to carry a descriptor, and
// returns the RAW descriptor number — not an *os.File.
//
// Raw on purpose. The only consumer hands it to
// tun.CreateUnmonitoredTUNFromFD, which wraps the number in an os.File of its
// own. Returning an *os.File here would mean two os.File values owning one
// descriptor, and the first one to be garbage collected would run its
// finalizer and close the device out from under the tunnel — a failure that
// would appear as the TUN dying at an unpredictable moment under memory
// pressure, which is close to the worst possible bug to have to find. The
// caller owns the number and must close it on every path that does not pass
// ownership on. -1 means no descriptor arrived.
//
// The single-read shape mirrors SendReplyWithFD's single sendmsg: a
// SOCK_STREAM unix socket preserves ancillary data's position in the byte
// stream, so the descriptor arrives with the bytes it was sent with. The frame
// is small and written in one call, so one read of a buffer larger than it
// gets the whole thing; a short read here would mean the sender did not use
// SendReplyWithFD, which is a protocol violation rather than something to
// reassemble.
func ReadReplyWithFD(c *net.UnixConn) (*Reply, int, error) {
	buf := make([]byte, 4+MaxFrame)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, -1, err
	}

	fd, fdErr := oneFDFrom(oob[:oobn])

	rep, err := decodeFrame(buf[:n])
	if err != nil {
		closeFD(fd)
		return nil, -1, err
	}
	if fdErr != nil {
		return nil, -1, fdErr
	}
	// A descriptor arriving with a reply that did not announce one is a
	// protocol violation, and leaking it would be worse than refusing: a TUN fd
	// nothing wraps is a device nothing closes.
	if fd >= 0 && !rep.TUNCreated {
		closeFD(fd)
		return nil, -1, errors.New("netdwire: unexpected file descriptor on a reply that did not announce one")
	}
	if fd < 0 && rep.TUNCreated && rep.OK {
		return nil, -1, errors.New("netdwire: reply announced a TUN descriptor but none arrived")
	}
	return rep, fd, nil
}

// oneFDFrom extracts exactly one descriptor from ancillary data, closing any
// extras rather than leaking them. Returns -1 when none arrived.
func oneFDFrom(oob []byte) (int, error) {
	if len(oob) == 0 {
		return -1, nil
	}
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return -1, fmt.Errorf("netdwire: parse control message: %w", err)
	}
	var got []int
	for i := range scms {
		fds, err := unix.ParseUnixRights(&scms[i])
		if err != nil {
			// Not a rights message (SCM_CREDENTIALS, say) — not an error.
			continue
		}
		got = append(got, fds...)
	}
	if len(got) == 0 {
		return -1, nil
	}
	// More than one is not something this protocol ever sends, so the extras
	// are closed rather than returned: leaking them would be a descriptor leak
	// per request, driven by the peer.
	for _, extra := range got[1:] {
		unix.Close(extra)
	}
	return got[0], nil
}

// closeFD closes a raw descriptor, ignoring -1.
func closeFD(fd int) {
	if fd >= 0 {
		unix.Close(fd)
	}
}

// PeerCred reads the connected peer's credentials. The kernel attaches these;
// an unprivileged process cannot forge them, which is what makes this a
// credential check rather than a claim (ADR-0049 §3.1).
func PeerCred(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, credErr
}
