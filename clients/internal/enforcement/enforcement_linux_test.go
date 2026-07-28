//go:build linux

package enforcement

import "testing"

// TestNewLinux pins New's honest-refusal contract: nil Enforcer, a
// NotImplementedError naming this GOOS and its tracking issue, not a panic
// or a silently usable zero value that a caller could mistake for a working
// Enforcer.
func TestNewLinux(t *testing.T) {
	e, err := New()
	if e != nil {
		t.Fatalf("New() Enforcer = %v, want nil", e)
	}
	niErr, ok := err.(NotImplementedError)
	if !ok {
		t.Fatalf("New() error type = %T, want NotImplementedError", err)
	}
	if niErr.GOOS != "linux" {
		t.Errorf("NotImplementedError.GOOS = %q, want %q", niErr.GOOS, "linux")
	}
	if niErr.Issue != "bacchus-vpn/bacchus#37" {
		t.Errorf("NotImplementedError.Issue = %q, want %q", niErr.Issue, "bacchus-vpn/bacchus#37")
	}
	if err.Error() == "" {
		t.Error("Error() is empty")
	}
}
