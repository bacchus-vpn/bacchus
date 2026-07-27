package coldstart

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"
)

// passthroughPkt is a packet that reached the caller of a demuxed conn's
// ReadFrom unmodified — i.e. Demux did not treat it as a bootstrap request.
type passthroughPkt struct {
	data []byte
	src  net.Addr
}

// startDemuxLoop wraps a fresh loopback UDP socket with Demux and drives its
// ReadFrom in a background goroutine, exactly as a pion/turn readLoop would,
// reporting every packet that comes back out (i.e. every packet Demux chose
// not to answer itself) on the returned channel.
func startDemuxLoop(t *testing.T, secrets SecretStore, snapshotFn func() []byte) (addr string, passthrough <-chan passthroughPkt) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	demuxed := Demux(pc, secrets, snapshotFn)

	ch := make(chan passthroughPkt, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, src, err := demuxed.ReadFrom(buf)
			if err != nil {
				return
			}
			ch <- passthroughPkt{data: append([]byte(nil), buf[:n]...), src: src}
		}
	}()
	t.Cleanup(func() {
		_ = pc.Close()
		<-done
	})
	return pc.LocalAddr().String(), ch
}

func dialTest(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve %s: %v", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestDemuxInterceptsAuthenticatedBootstrap(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secretID, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	store := NewMemStore()
	store.Add(secretID, secret)
	signed, err := Sign(priv, testSnapshot())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	addr, passthrough := startDemuxLoop(t, store, func() []byte { return signed })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := Bootstrap(ctx, addr, secretID, secret, pub)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(res.Snapshot.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(res.Snapshot.Entries))
	}

	select {
	case pkt := <-passthrough:
		t.Fatalf("authenticated bootstrap request should not pass through, got %d bytes from %s", len(pkt.data), pkt.src)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestDemuxRejectsWrongSecret(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	secretID, secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	store := NewMemStore()
	store.Add(secretID, secret)
	signed, _ := Sign(priv, testSnapshot())

	addr, _ := startDemuxLoop(t, store, func() []byte { return signed })

	_, wrongSecret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := Bootstrap(ctx, addr, secretID, wrongSecret, pub); err != ErrNotAuthenticated {
		t.Fatalf("Bootstrap with wrong secret: err = %v, want ErrNotAuthenticated", err)
	}
}

func TestDemuxPassesThroughPlainBindingRequest(t *testing.T) {
	addr, passthrough := startDemuxLoop(t, NewMemStore(), func() []byte { return nil })
	conn := dialTest(t, addr)

	req := buildRequest(newTxID(), "", nil) // no key => bare Binding Request, FINGERPRINT only
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case pkt := <-passthrough:
		if string(pkt.data) != string(req) {
			t.Fatalf("passthrough packet mismatch:\n got  %x\n want %x", pkt.data, req)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("plain Binding Request (no USERNAME) was not passed through")
	}
}

func TestDemuxPassesThroughNonSTUNGarbage(t *testing.T) {
	addr, passthrough := startDemuxLoop(t, NewMemStore(), func() []byte { return nil })
	conn := dialTest(t, addr)

	garbage := []byte("not a stun packet at all")
	if _, err := conn.Write(garbage); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case pkt := <-passthrough:
		if string(pkt.data) != string(garbage) {
			t.Fatalf("passthrough packet mismatch:\n got  %x\n want %x", pkt.data, garbage)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("non-STUN garbage was not passed through")
	}
}

// TestDemuxPassesThroughOtherSTUNMethodsEvenWithUsername pins the routing
// rule that the message *type* decides interception, not merely the
// presence of USERNAME — a real TURN Allocate/Refresh/CreatePermission/
// ChannelBind request also carries USERNAME (TURN long-term credentials),
// and must reach pion/turn unchanged rather than being swallowed here.
func TestDemuxPassesThroughOtherSTUNMethodsEvenWithUsername(t *testing.T) {
	addr, passthrough := startDemuxLoop(t, NewMemStore(), func() []byte { return nil })
	conn := dialTest(t, addr)

	const typeAllocateRequest = 0x0003
	attrs := []attribute{{attrUsername, []byte("deadbeefdeadbeef")}}
	body := encodeAttrs(attrs)
	fake := append(encodeHeader(typeAllocateRequest, newTxID(), len(body)), body...)

	if _, err := conn.Write(fake); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case pkt := <-passthrough:
		if string(pkt.data) != string(fake) {
			t.Fatalf("passthrough packet mismatch:\n got  %x\n want %x", pkt.data, fake)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("non-Binding STUN request was not passed through despite carrying USERNAME")
	}
}
