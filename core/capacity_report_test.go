package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
)

// mintCosignedReceipt runs the real exit and client accounting halves over an in-memory
// pipe and returns a genuinely co-signed receipt plus the client key that signed it — the
// same shape runClientAccounting holds when it sends a capacity-report (issue #158).
func mintCosignedReceipt(t *testing.T, exitID string, bytesN uint64) (accounting.Receipt, ed25519.PrivateKey) {
	t.Helper()
	_, exitKey, _ := ed25519.GenerateKey(rand.Reader)
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	a, b := net.Pipe()
	type res struct {
		r   accounting.Receipt
		err error
	}
	ch := make(chan res, 1)
	go func() {
		r, err := accounting.ClientCosign(b, clientKey, bytesN)
		ch <- res{r, err}
	}()
	if _, err := accounting.ExitPropose(a, exitKey, exitID, "sess", 0, 60, bytesN); err != nil {
		t.Fatalf("ExitPropose: %v", err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("ClientCosign: %v", got.err)
	}
	_ = a.Close()
	_ = b.Close()
	return got.r, clientKey
}

// TestSendCapacityReportProducesAcceptableReport proves the client assembles a
// capacity-report the coordinator will accept: the right message type and credential, a
// receipt that still co-verifies, and a report signature the coordinator's VerifyReport
// checks out. This is the client end of the feed the coordinator tests drive from crafted
// messages.
func TestSendCapacityReportProducesAcceptableReport(t *testing.T) {
	// A UDP listener stands in for the coordinator; a coordLink dialed to it captures
	// exactly the datagram sendCapacityReport puts on the wire.
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.DialUDP("udp", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	l := &coordLink{conn: conn}

	e := &Engine{cfg: Config{AdmissionCred: "client-cred-xyz"}}
	r, clientKey := mintCosignedReceipt(t, "exit-1", 3_000_000)
	e.sendCapacityReport(r, clientKey, &accounting.Counter{}, l)

	_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)
	n, _, err := ln.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no capacity-report datagram arrived: %v", err)
	}
	var m wire
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if m.Type != "capacity-report" {
		t.Errorf("report type = %q, want capacity-report", m.Type)
	}
	if m.Cred != "client-cred-xyz" {
		t.Errorf("report cred = %q, want the client's admission credential", m.Cred)
	}
	if m.Receipt == nil {
		t.Fatal("report carried no receipt")
	}
	if err := m.Receipt.Verify(); err != nil {
		t.Errorf("the co-signed receipt did not survive the round trip: %v", err)
	}
	if err := accounting.VerifyReport(*m.Receipt, m.ReportSig); err != nil {
		t.Errorf("the report signature did not verify against the receipt's client key: %v", err)
	}
}

// TestSendCapacityReportNilLinkIsNoop: a session with no live coordinator link sends
// nothing rather than panicking — a missed sample, not a crash.
func TestSendCapacityReportNilLinkIsNoop(t *testing.T) {
	e := &Engine{cfg: Config{AdmissionCred: "x"}}
	r, clientKey := mintCosignedReceipt(t, "exit-1", 1000)
	e.sendCapacityReport(r, clientKey, &accounting.Counter{}, nil) // must not panic
}
