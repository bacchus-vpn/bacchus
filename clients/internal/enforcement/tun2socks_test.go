package enforcement

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// fakeSOCKS5 accepts one no-auth SOCKS5 CONNECT handshake per connection (the
// same subset core/client.go's own SOCKS5 server implements) and then hands
// the raw connection to handle, ignoring the requested target — enough to
// exercise dialSOCKS/resolveDNSOverTCP's client-side framing without needing
// a live coordinator/exit.
func fakeSOCKS5(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if !socks5Handshake(c) {
					return
				}
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// socks5Handshake performs the server side of a no-auth SOCKS5 CONNECT
// negotiation and reports whether it succeeded.
func socks5Handshake(c net.Conn) bool {
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
		return false
	}
	if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
		return false
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return false
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 1 {
		return false
	}
	switch buf[3] {
	case 1:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return false
		}
	case 3:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return false
		}
		if _, err := io.ReadFull(c, buf[:int(buf[0])]); err != nil {
			return false
		}
	case 4:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return false
		}
	default:
		return false
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return false
	}
	_, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	return err == nil
}

func TestDialSOCKSHandshake(t *testing.T) {
	got := make(chan string, 1)
	addr := fakeSOCKS5(t, func(c net.Conn) {
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		got <- string(buf[:n])
	})

	conn, err := dialSOCKS(addr, "9.9.9.9:53")
	if err != nil {
		t.Fatalf("dialSOCKS: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case msg := <-got:
		if msg != "hello" {
			t.Fatalf("server received %q, want %q", msg, "hello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proxied bytes")
	}
}

func TestResolveDNSOverTCP(t *testing.T) {
	query := []byte("fake dns query")
	answer := []byte("fake dns answer")

	addr := fakeSOCKS5(t, func(c net.Conn) {
		var lenPrefix [2]byte
		if _, err := io.ReadFull(c, lenPrefix[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(lenPrefix[:])
		got := make([]byte, n)
		if _, err := io.ReadFull(c, got); err != nil {
			return
		}
		if !bytes.Equal(got, query) {
			t.Errorf("upstream received query %q, want %q", got, query)
		}
		binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(answer)))
		_, _ = c.Write(lenPrefix[:])
		_, _ = c.Write(answer)
	})

	resp, err := resolveDNSOverTCP(query, addr, "9.9.9.9:53")
	if err != nil {
		t.Fatalf("resolveDNSOverTCP: %v", err)
	}
	if !bytes.Equal(resp, answer) {
		t.Fatalf("resolveDNSOverTCP = %q, want %q", resp, answer)
	}
}
