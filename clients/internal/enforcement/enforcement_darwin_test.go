//go:build darwin

package enforcement

import "testing"

// TestNewDarwin mirrors TestNewLinux (enforcement_linux_test.go) — see its
// doc. Only actually runs on a darwin host or under GOOS=darwin cross-tooling;
// this dev environment and this repo's CI are both Linux, so it is verified
// by inspection against enforcement_linux_test.go's identical shape and by
// `go vet`/`gofmt` cross-checked with GOOS=darwin, not by a local `go test`
// run — same limitation clients/fyne/internal/appstate's own
// autostart_windows_test.go already has on this same Linux-only CI.
func TestNewDarwin(t *testing.T) {
	e, err := New()
	if e != nil {
		t.Fatalf("New() Enforcer = %v, want nil", e)
	}
	niErr, ok := err.(NotImplementedError)
	if !ok {
		t.Fatalf("New() error type = %T, want NotImplementedError", err)
	}
	if niErr.GOOS != "darwin" {
		t.Errorf("NotImplementedError.GOOS = %q, want %q", niErr.GOOS, "darwin")
	}
	if niErr.Issue != "bacchus-vpn/bacchus#36" {
		t.Errorf("NotImplementedError.Issue = %q, want %q", niErr.Issue, "bacchus-vpn/bacchus#36")
	}
	if err.Error() == "" {
		t.Error("Error() is empty")
	}
}
