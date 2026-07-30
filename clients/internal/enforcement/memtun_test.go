package enforcement

import (
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// memTun is a tun.Device backed by two in-memory packet queues instead of a
// kernel interface: what the netstack writes comes out of toDevice, and
// whatever is pushed into toStack is what the netstack reads.
//
// It exists so the enforced data path can be driven end to end without root,
// without an OS TUN device, and on any GOOS — which is what makes parity item
// 8's traffic test something CI runs on every push rather than something a
// human confirms by hand on an elevated Windows box once. The netstack, the
// SOCKS bridge, the engine, the transport and the exit on the far side of it
// are all real; the wire under the device is the only simulated part, and it
// is simulated at the layer where "a real byte" is still a real IP packet.
type memTun struct {
	toStack  chan []byte // packets the "OS side" is sending into the netstack
	toDevice chan []byte // packets the netstack is sending out to the "OS side"
	events   chan tun.Event

	closeOnce sync.Once
	closed    chan struct{}
}

func newMemTun() *memTun {
	return &memTun{
		toStack:  make(chan []byte, 256),
		toDevice: make(chan []byte, 256),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
}

func (m *memTun) File() *os.File { return nil }

func (m *memTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-m.toStack:
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	case <-m.closed:
		return 0, os.ErrClosed
	}
}

func (m *memTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := append([]byte(nil), b[offset:]...)
		select {
		case m.toDevice <- pkt:
		case <-m.closed:
			return 0, os.ErrClosed
		default:
			// Drop rather than block: a full queue means the far end stopped
			// reading, and stalling the netstack's outbound pump would wedge
			// the test instead of failing it.
		}
	}
	return len(bufs), nil
}

func (m *memTun) MTU() (int, error)        { return 1420, nil }
func (m *memTun) Name() (string, error)    { return "bacchus-test", nil }
func (m *memTun) Events() <-chan tun.Event { return m.events }
func (m *memTun) BatchSize() int           { return 1 }
func (m *memTun) isClosed() bool {
	select {
	case <-m.closed:
		return true
	default:
		return false
	}
}

func (m *memTun) Close() error {
	m.closeOnce.Do(func() { close(m.closed) })
	return nil
}
