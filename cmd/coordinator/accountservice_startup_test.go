// The -account-service startup line (issue #260) — the one gate
// deploy/bacchus-gate-check.sh could not read.
//
// Two tests, and they answer two different questions on purpose. The first pins
// the FORMAT, because a shell reader in another language matches ASCII substrings
// of these bytes and a format nobody pinned is a contract nobody can hold. The
// second proves the line is actually EMITTED, by a real coordinator, into the
// window that check keys on — which is the only question the card is about. A
// format test alone would stay green over a log.Print that was never wired, and
// the whole defect being fixed here is a fact the binary knew and did not say.

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The two spellings, exactly. deploy/bacchus-gate-check.sh (ADR-0072) reads
// posture out of the journal rather than out of ExecStart, deliberately: a flag
// says what an operator asked for and a journal line says what the binary
// concluded. That makes these strings a cross-language contract, so they change
// together with that reader or not at all.
func TestAccountServicePublicationLineFormat(t *testing.T) {
	const prefix = "account service: "
	for _, tc := range []struct {
		name string
		n    int
		want string
	}{
		{
			name: "none",
			n:    0,
			want: "account service: NONE published (-account-service unset) — every client stays on its own configuration (issue #193)",
		},
		{
			name: "one",
			n:    1,
			want: `account service: 1 address(es) published in the signed directory as role "account" (issue #193)`,
		},
		{
			name: "several",
			n:    3,
			want: `account service: 3 address(es) published in the signed directory as role "account" (issue #193)`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := describeAccountServicePublication(tc.n)
			if got != tc.want {
				t.Fatalf("describeAccountServicePublication(%d) =\n  %q\nwant\n  %q", tc.n, got, tc.want)
			}
			if !strings.HasPrefix(got, prefix) {
				t.Fatalf("every spelling must begin %q so one substring test answers whether the "+
					"window said anything at all; got %q", prefix, got)
			}
		})
	}
	// The empty case must not be mistakable for the configured one by a reader
	// looking for the count. "0 address(es)" would satisfy an index() on the
	// configured prefix and report a publication that does not exist.
	if strings.Contains(describeAccountServicePublication(0), "address(es) published") {
		t.Fatal("the empty spelling contains the configured spelling's substring, so a reader " +
			"matching on it would read NONE published as a publication (issue #260)")
	}
}

// A real coordinator says it, in the window bacchus-gate-check.sh reads.
//
// The window opens at the "coordinator release " line — that is where the shell
// reader resets every gate row — so a line printed before it describes a
// coordinator that is gone. Both spellings are therefore asserted to arrive
// AFTER that line, not merely to arrive.
func TestACoordinatorStatesItsAccountServicePublication(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH, so this build-and-run check cannot run: %v", err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "bacchus-coordinator")
	build := exec.Command("go", "build", "-o", bin, "./cmd/coordinator")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building cmd/coordinator: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		name  string
		flags []string
		want  string
	}{
		{
			name:  "unset",
			flags: nil,
			want:  "account service: NONE published",
		},
		{
			// example.com, never a real address: this repository is public and
			// carries no infrastructure address of any kind.
			name:  "two addresses",
			flags: []string{"-account-service", "https://one.example.com", "-account-service", "https://two.example.com:8443"},
			want:  `account service: 2 address(es) published in the signed directory as role "account"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := []string{
				"-addr", localUDP(t),
				"-turn-addr", localUDP(t),
				// RFC 5737 documentation address. TURN needs a public IP to
				// hand out and refuses to start without one.
				"-turn-public-ip", "192.0.2.1",
				"-turn-pass", "not-a-real-password",
			}
			args = append(args, tc.flags...)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			run := exec.CommandContext(ctx, bin, args...)
			// Relative secrets/ paths and the generated bootstrap key land here
			// rather than in the repository.
			run.Dir = dir
			stderr, err := run.StderrPipe()
			if err != nil {
				t.Fatalf("stderr pipe: %v", err)
			}
			if err := run.Start(); err != nil {
				t.Fatalf("starting the coordinator: %v", err)
			}
			defer func() {
				cancel()
				_ = run.Wait()
			}()

			// Read until the line arrives or the process gives up. Nothing here
			// waits a fixed duration: the coordinator prints this before it binds
			// anything, so a sleep would only decide how long a failure takes.
			var seen []string
			windowOpen := false
			found := false
			sc := bufio.NewScanner(stderr)
			for sc.Scan() {
				line := sc.Text()
				seen = append(seen, line)
				if strings.Contains(line, "coordinator release ") {
					windowOpen = true
				}
				if strings.Contains(line, tc.want) {
					if !windowOpen {
						t.Fatalf("the account-service line arrived BEFORE the \"coordinator release \" "+
							"line. That line is where deploy/bacchus-gate-check.sh opens its window and "+
							"resets every gate row, so anything printed above it is attributed to the "+
							"coordinator that is gone (issues #249, #260). Journal so far:\n%s",
							strings.Join(seen, "\n"))
					}
					found = true
					break
				}
				// The listening line is the last thing before the packet loop; if
				// the account-service line has not arrived by then it never will.
				if strings.Contains(line, "listening on") {
					break
				}
			}
			if !found {
				t.Fatalf("no line containing %q in the coordinator's startup journal. Every other "+
					"configured gate announces itself and this one is what bacchus-gate-check.sh "+
					"reports UNKNOWN without (issue #260). What it printed:\n%s",
					tc.want, strings.Join(seen, "\n"))
			}
		})
	}
}

// localUDP returns a loopback host:port nothing is listening on, by binding one
// and letting it go. A fixed port would make two packages running in parallel
// collide, and the default :8080/:3478 would reach for whatever the developer
// already has running.
func localUDP(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a loopback UDP port: %v", err)
	}
	defer c.Close()
	addr := c.LocalAddr().(*net.UDPAddr)
	return fmt.Sprintf("127.0.0.1:%d", addr.Port)
}
