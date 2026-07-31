// The encoding, tested on its own. Everything here runs as root in production
// — this is the decoder an unprivileged local process feeds — so the cases that
// matter most are the malformed ones.
package netdwire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := &Request{
		Version:  Version,
		Verb:     VerbAddExclusionRoutes,
		Token:    "abc",
		Prefixes: []string{"192.0.2.0/24", "198.51.100.7/32"},
	}
	if err := WriteFrame(&buf, want); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got.Verb != want.Verb || got.Token != want.Token || len(got.Prefixes) != 2 {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

// The cap must be applied to the length PREFIX, before any buffer is
// allocated. Validating after make() would defeat the point: the sender is an
// unprivileged process that can claim any size it likes, and "the helper
// allocated 4GiB because the prefix said so" is a denial of service against the
// machine's networking, run as root.
func TestOversizedLengthPrefixIsRejectedBeforeAllocating(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], ^uint32(0)) // 4GiB
	// Deliberately NO body: if the implementation allocated first and read
	// second, this would block or OOM rather than return.
	_, err := ReadRequest(bytes.NewReader(hdr[:]))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadRequest error = %v, want ErrFrameTooLarge", err)
	}
}

// Unknown fields are refused rather than ignored. Silently dropping a field the
// sender thought mattered is how a version skew becomes a wrong-but-accepted
// request — the helper would act on a partial instruction believing it was
// whole.
func TestUnknownFieldsAreRefused(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"version": Version, "verb": VerbOpen, "surprise": "hello",
	})
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	buf.Write(hdr[:])
	buf.Write(body)

	_, err := ReadRequest(&buf)
	if err == nil {
		t.Fatal("ReadRequest accepted an unknown field")
	}
	var perr *ProtocolError
	if !errors.As(err, &perr) || perr.Code != CodeBadRequest {
		t.Errorf("error = %v, want a ProtocolError with code %q", err, CodeBadRequest)
	}
}

// Version is compared for EQUALITY, not ">=". ADR-0049's Consequences require a
// mismatched pair to refuse each other outright rather than negotiate down to a
// subset — a client that silently lost its kill-switch to a version skew is
// parity item 7's failure wearing different clothes.
func TestVersionMismatchIsRefusedInBothDirections(t *testing.T) {
	for _, v := range []int{Version - 1, Version + 1, 0} {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, &Request{Version: v, Verb: VerbOpen}); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
		_, err := ReadRequest(&buf)
		var perr *ProtocolError
		if !errors.As(err, &perr) || perr.Code != CodeVersion {
			t.Errorf("version %d: error = %v, want code %q", v, err, CodeVersion)
			continue
		}
		// The message has to name what to fix; the user cannot guess "reinstall
		// both halves" from "refused".
		if !strings.Contains(perr.Message, "bacchus-netd") {
			t.Errorf("version %d: message does not say what to reinstall: %q", v, perr.Message)
		}
	}
}

func TestListsAreCapped(t *testing.T) {
	long := make([]string, MaxList+1)
	for i := range long {
		long[i] = "192.0.2.1/32"
	}
	for name, req := range map[string]*Request{
		"prefixes": {Version: Version, Verb: VerbAddExclusionRoutes, Prefixes: long},
		"control":  {Version: Version, Verb: VerbEnableKillSwitch, Control: long},
		"bypass":   {Version: Version, Verb: VerbEnableKillSwitch, Bypass: long},
	} {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, req); err != nil {
			t.Fatalf("%s: WriteFrame: %v", name, err)
		}
		_, err := ReadRequest(&buf)
		var perr *ProtocolError
		if !errors.As(err, &perr) || perr.Code != CodeBadRequest {
			t.Errorf("%s: error = %v, want code %q", name, err, CodeBadRequest)
		}
	}
}

func TestAVerblessRequestIsRefused(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Request{Version: Version}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	_, err := ReadRequest(&buf)
	var perr *ProtocolError
	if !errors.As(err, &perr) || perr.Code != CodeBadRequest {
		t.Errorf("error = %v, want code %q", err, CodeBadRequest)
	}
}

// A truncated frame must be an error, not a partially-decoded request. A
// half-read prefix list would be a subset of what the client asked for, applied
// as though it were the whole of it.
func TestATruncatedFrameIsAnError(t *testing.T) {
	var full bytes.Buffer
	if err := WriteFrame(&full, &Request{
		Version: Version, Verb: VerbAddExclusionRoutes, Prefixes: []string{"192.0.2.0/24"},
	}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	b := full.Bytes()
	if _, err := ReadRequest(bytes.NewReader(b[:len(b)-3])); err == nil {
		t.Error("ReadRequest accepted a truncated frame")
	}
}

// A reply's refusal must survive the trip as a typed code, so callers branch on
// a value rather than matching message text.
func TestReplyErrCarriesTheCode(t *testing.T) {
	if err := (&Reply{OK: true}).Err(); err != nil {
		t.Errorf("Err() on a successful reply = %v, want nil", err)
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, Failf(CodeBusy, "another session is open")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	rep, err := ReadReply(&buf)
	if err != nil {
		t.Fatalf("ReadReply: %v", err)
	}
	var perr *ProtocolError
	if !errors.As(rep.Err(), &perr) || perr.Code != CodeBusy {
		t.Errorf("Err() = %v, want a ProtocolError with code %q", rep.Err(), CodeBusy)
	}
}

// ReadReply tolerates unknown fields where ReadRequest refuses them. The
// asymmetry is deliberate: this direction runs in the unprivileged client,
// against a helper it already refused to talk to on any version mismatch, so
// strictness buys nothing and would turn a harmless additive field into a hard
// failure.
func TestReadReplyToleratesUnknownFields(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"ok": true, "future_field": 1})
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	buf.Write(hdr[:])
	buf.Write(body)

	rep, err := ReadReply(&buf)
	if err != nil {
		t.Fatalf("ReadReply: %v", err)
	}
	if !rep.OK {
		t.Error("reply did not decode as OK")
	}
}
