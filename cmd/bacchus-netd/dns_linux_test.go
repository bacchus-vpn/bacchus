//go:build linux

// The no-resolved DNS fallback, against a real filesystem.
//
// Every assertion below reads the file back with os.Lstat/os.Readlink/
// os.ReadFile — the kernel's own view — rather than re-reading anything this
// package encoded. That is the same rule the netlink and nftables tests follow
// and it matters more here than it looks: the bug this code can actually have
// is not "wrote the wrong bytes", it is "restored a symlink as a regular file",
// which only a stat can see.
//
// What is NOT covered here, and is not coverable here: the systemd-resolved
// path. It needs a session bus and a running resolved, which this package's
// namespace harness does not have. ADR-0051 records how it was verified instead
// (the real resolved driven inside a user + network namespace) and proposes the
// CI step that would automate it.
package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// withTempResolvConf points the fallback at a scratch path for one test.
func withTempResolvConf(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	prior := resolvConf
	resolvConf = path
	t.Cleanup(func() { resolvConf = prior })
	return path
}

func captureSession(t *testing.T) *session {
	t.Helper()
	return &session{tunIndex: 42, tunAddr: netip.MustParseAddr("10.66.0.2")}
}

// TestFallbackRestoresARegularFileByteForByte is the ordinary case: something
// on the machine owns /etc/resolv.conf as a plain file, and it has to come back
// exactly, contents and mode.
func TestFallbackRestoresARegularFileByteForByte(t *testing.T) {
	path := withTempResolvConf(t)
	original := "nameserver 192.0.2.53\noptions timeout:1\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	h := newHelper(t.Logf, false)
	sess := captureSession(t)
	if err := h.captureViaResolvConf(sess, tunDNSSink(sess.tunAddr)); err != nil {
		t.Fatalf("captureViaResolvConf: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == original {
		t.Fatal("capture left the file unchanged; nothing was captured")
	}
	if want := "nameserver 10.66.0.53"; !containsLine(string(got), want) {
		t.Errorf("captured resolv.conf does not point at the tunnel\ngot:\n%s\nwant a line: %s", got, want)
	}

	h.releaseViaResolvConf(sess)

	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Errorf("resolv.conf was not restored byte for byte\ngot:\n%q\nwant:\n%q", restored, original)
	}
}

// TestFallbackRestoresASymlinkAsASymlink is the case that actually bites. A
// resolvconf or NetworkManager machine has /etc/resolv.conf as a symlink;
// replacing it with a regular file and then "restoring" a regular file would
// silently detach the machine from whatever manages it, and every content-level
// assertion would still pass.
func TestFallbackRestoresASymlinkAsASymlink(t *testing.T) {
	path := withTempResolvConf(t)
	target := filepath.Join(filepath.Dir(path), "upstream-resolv.conf")
	if err := os.WriteFile(target, []byte("nameserver 192.0.2.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	h := newHelper(t.Logf, false)
	sess := captureSession(t)
	if err := h.captureViaResolvConf(sess, tunDNSSink(sess.tunAddr)); err != nil {
		t.Fatalf("captureViaResolvConf: %v", err)
	}

	// While captured it must be a regular file, or we have not displaced the
	// manager we were trying to displace.
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("capture left the symlink in place, so the machine is still resolving through whatever it points at")
	}

	h.releaseViaResolvConf(sess)

	fi, err = os.Lstat(path)
	if err != nil {
		t.Fatalf("resolv.conf is missing after release: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("a symlink was restored as a regular file — the machine is now detached from whatever managed its resolver, and its contents will never be updated again")
	}
	got, err := os.Readlink(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Errorf("symlink restored to %q, want %q", got, target)
	}
}

// TestFallbackRemovesWhatItWroteWhenThereWasNothing covers the third prior
// state. A machine with no /etc/resolv.conf at all must not be left owning one
// we invented.
func TestFallbackRemovesWhatItWroteWhenThereWasNothing(t *testing.T) {
	path := withTempResolvConf(t)

	h := newHelper(t.Logf, false)
	sess := captureSession(t)
	if err := h.captureViaResolvConf(sess, tunDNSSink(sess.tunAddr)); err != nil {
		t.Fatalf("captureViaResolvConf: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("capture wrote no resolv.conf: %v", err)
	}

	h.releaseViaResolvConf(sess)

	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("release left a resolv.conf behind on a machine that had none (err=%v)", err)
	}
}

// TestReleaseDNSRestoresWithoutTheClientAsking is the crash property, at the
// level the helper actually implements it: releaseDNS is driven from the
// session, so the disconnect path can undo a capture with no client left to ask.
// ADR-0051 §4 — the one piece of session state deliberately NOT held past a
// crash, unlike the kill-switch.
func TestReleaseDNSRestoresWithoutTheClientAsking(t *testing.T) {
	path := withTempResolvConf(t)
	original := "nameserver 192.0.2.53\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	h := newHelper(t.Logf, false)
	sess := captureSession(t)
	if err := h.captureViaResolvConf(sess, tunDNSSink(sess.tunAddr)); err != nil {
		t.Fatalf("captureViaResolvConf: %v", err)
	}

	// releaseDNS, not releaseViaResolvConf: this is the path clientGone takes,
	// and it has to route to the right mechanism off the recorded state.
	h.releaseDNS(sess)

	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Errorf("the disconnect path did not restore the resolver\ngot %q, want %q", restored, original)
	}
	if sess.dns.captured {
		t.Error("session still reports DNS captured after release, so a second release would try to restore twice")
	}
}

// TestTunDNSSinkNeverNamesTheTunsOwnAddress pins the one arithmetic detail with
// a real failure behind it. The TUN's own address is in the kernel's `local`
// table, so a query aimed at it goes to loopback and never reaches the device —
// the same class of mistake as the 127.0.0.53 problem this whole card is about.
func TestTunDNSSinkNeverNamesTheTunsOwnAddress(t *testing.T) {
	for _, tunAddr := range []string{"10.66.0.2", "10.66.0.53", "10.66.0.1", "192.0.2.53"} {
		addr := netip.MustParseAddr(tunAddr)
		sink := tunDNSSink(addr)
		if sink == addr {
			t.Errorf("tunDNSSink(%s) returned the TUN's own address; queries to it would go to loopback, not the tunnel", tunAddr)
		}
		if sink.As4()[0] != addr.As4()[0] || sink.As4()[1] != addr.As4()[1] || sink.As4()[2] != addr.As4()[2] {
			t.Errorf("tunDNSSink(%s) = %s, which is off the tunnel's /24 and so not on-link", tunAddr, sink)
		}
	}
}

func containsLine(body, want string) bool {
	for _, line := range splitLines(body) {
		if line == want {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
