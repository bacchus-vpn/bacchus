package core

import (
	"bytes"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// buildChromeHello returns a real uTLS Chrome ClientHello (record-framed) plus the
// fields peekClientHello must recover from it, so the parser is tested against the
// exact bytes a client emits, not a hand-rolled approximation.
func buildChromeHello(t *testing.T) (record []byte, random, sessionID, x25519 []byte) {
	t.Helper()
	c, _ := net.Pipe()
	defer c.Close()
	u := utls.UClient(c, &utls.Config{ServerName: "www.example.com", InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	if err := u.MarshalClientHello(); err != nil {
		t.Fatalf("MarshalClientHello: %v", err)
	}
	h := u.HandshakeState.Hello
	if len(h.Raw) == 0 {
		t.Fatal("marshalled ClientHello is empty")
	}
	for _, ks := range h.KeyShares {
		if ks.Group == tlsGroupX25519 {
			x25519 = ks.Data
		}
	}
	if len(x25519) != 32 {
		t.Fatalf("no 32-byte x25519 key share in the hello (got %d bytes)", len(x25519))
	}
	record = append([]byte{tlsRecordHandshake, 3, 1, byte(len(h.Raw) >> 8), byte(len(h.Raw))}, h.Raw...)
	return record, h.Random, h.SessionId, x25519
}

func TestPeekClientHelloParsesRealHello(t *testing.T) {
	record, random, sessionID, x25519 := buildChromeHello(t)

	raw, hello, err := peekClientHello(bytes.NewReader(record))
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if !bytes.Equal(raw, record) {
		t.Fatalf("raw peeked bytes (%d) do not match the record (%d)", len(raw), len(record))
	}
	if !bytes.Equal(hello.random, random) {
		t.Fatal("parsed random does not match the hello")
	}
	if !bytes.Equal(hello.sessionID, sessionID) {
		t.Fatal("parsed session id does not match the hello")
	}
	if !bytes.Equal(hello.x25519, x25519) {
		t.Fatal("parsed x25519 key share does not match the hello")
	}
}

// TestPeekClientHelloRejectsNonHandshake proves a plaintext (non-TLS) request is
// reported as not-a-ClientHello, while the bytes it consumed are still returned so
// the caller can splice them to the origin.
func TestPeekClientHelloRejectsNonHandshake(t *testing.T) {
	raw, hello, err := peekClientHello(bytes.NewReader([]byte("GET / HTTP/1.1\r\n\r\n")))
	if err != errNotClientHello {
		t.Fatalf("err = %v, want errNotClientHello", err)
	}
	if hello != nil {
		t.Fatal("hello should be nil for non-handshake bytes")
	}
	if string(raw) != "GET /" { // exactly the 5-byte record header it read
		t.Fatalf("raw = %q, want the 5 bytes consumed", raw)
	}
}

func TestPeekClientHelloTruncated(t *testing.T) {
	raw, _, err := peekClientHello(bytes.NewReader([]byte{tlsRecordHandshake, 3}))
	if err == nil {
		t.Fatal("want an error on a truncated record header")
	}
	if len(raw) != 2 {
		t.Fatalf("raw = %d bytes, want the 2 consumed", len(raw))
	}
}

func TestPrefixConnReplays(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	prefix := []byte("PREFIX")
	pc := &prefixConn{Conn: b, prefix: append([]byte(nil), prefix...)}

	go func() {
		_, _ = a.Write([]byte("-LIVE"))
		_ = a.Close()
	}()

	got := make([]byte, 0, 16)
	buf := make([]byte, 4)
	for {
		n, err := pc.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	if string(got) != "PREFIX-LIVE" {
		t.Fatalf("prefixConn read %q, want %q", got, "PREFIX-LIVE")
	}
}
