package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/accountclient"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
)

// The node's half of the device-credential lifecycle (issue #170, ADR-0071):
// how a node gets a credential, and how it keeps one.
//
// # Why this is not a -claim-code flag
//
// ADR-0056 §3 ruled the flag out and the reasoning is worth having here rather
// than one citation away, because every alternative below is shaped by it.
//
// A claim code is a bearer secret spent exactly once. A flag is re-supplied on
// every start — it lives in a unit file, a shell history and a process listing,
// and it is presented again by every restart. clients/fyne can accept one in a
// config file because a config file can be REWRITTEN: it erases the code the
// moment enrollment succeeds. A command line cannot erase itself.
//
// # What this binary does instead: a one-shot mode, not a daemon input
//
// -enroll runs the exchange and exits. The service that runs afterwards is given
// no claim code at all, under any name, so there is nothing for a restart to
// re-present. That is a stronger guarantee than erase-on-success, which depends
// on a write succeeding after the irreversible step already has.
//
// The code itself is read from stdin, or from a file named by -claim-code-file
// that is UNLINKED once it has bought a credential. Stdin is the documented
// default because a code piped in never reaches a disk at all; the file exists
// for an unattended provisioning flow that finds dropping a file easier than
// feeding a pipe.
//
// A flag one-shot rather than a subcommand: -list is this binary's existing
// precedent for "do one thing and quit", and cmd/node parses with the flag
// package alone. Adding os.Args[1] dispatch would change how every existing
// invocation parses in order to gain nothing that -enroll does not already have.
//
// # And the alternative that lost: a file the DAEMON consumes and unlinks
//
// It is the closest rival and it fails on the same seam it was invented to fix.
// The unlink is a second operation, after the one that cannot be repeated, and
// its failure — a read-only filesystem, a directory the service cannot write —
// leaves a spent code on disk for the next start to present, which is the exact
// outcome ADR-0056 refused. It also puts a network call to the account service
// on the startup path of a node whose job is to forward packets, and it forces
// the daemon to decide what a claim-code file MEANS beside a device that is
// already enrolled: the code may be for a different device entirely, so neither
// deleting it nor keeping it is right.
//
// Provisioning and running are different lifecycles. This keeps them in
// different invocations.

// defaultDeviceLabel is what the account's owner sees this node called in their
// own device list.
//
// It is a word, and it is NEVER derived from the machine. clients/fyne defaults
// to "desktop" for the reason its Config.DeviceLabel doc gives — a hostname is a
// username on most desktops and a real name on many — and a server's hostname is
// no better: it is routinely the provider's, the datacenter's, or the operator's
// own name, it travels to the account service in the clear, and it is stored
// there durably. An operator who wants this node distinguishable says so with
// -device-label.
const defaultDeviceLabel = "node"

// accountFlags is this node's account-service configuration. A struct rather
// than loose flags so main's flag block stays one line per concern, matching
// updateFlags next door.
type accountFlags struct {
	service  *string
	audience *string
	ca       *string
	label    *string
	enroll   *bool
	codeFile *string
}

// registerAccountFlags declares the account-service flags on the default flag
// set.
func registerAccountFlags() accountFlags {
	return accountFlags{
		service:  flag.String("account-service", "", "client: the account service's address(es), comma-separated, scheme and host only — https://host:port (issue #170, ADR-0071). This is where this node enrolls and renews the device credential -device-cred-dir holds. Empty is a complete configuration and not a degraded one: a deployment with no account service configures nothing here, enrolls nothing, and renews nothing. Several addresses are several LOCATIONS of ONE service, tried in order (issue #192) — they share one audience and one pinned CA, which is what keeps a second address from quietly becoming a second authority. The address is operator-supplied and never discovered"),
		audience: flag.String("account-service-audience", "", "client: the account service's own identity, bound into every assertion this node signs for it. Required with -account-service, pinned out of band, and NEVER read out of a response — a client that learned it from the reply it is about to sign against would let the responder choose the binding"),
		ca:       flag.String("account-service-ca", "", "client: PEM file holding the certificate that authenticates the account service's TLS identity. REQUIRED with -account-service, and the system's public root pool is deliberately not consulted even as a fallback: the service sits behind a camouflaged front under an unremarkable name, so a publicly-trusted certificate for that name authenticates the decoy"),
		label:    flag.String("device-label", "", "client: what the account's owner sees this node called in their own device list. It travels to the account service in the clear and is stored there durably, so it is never derived from this machine — a server hostname is routinely the provider's, the datacenter's, or a person's name. Empty uses \""+defaultDeviceLabel+"\""),
		enroll:   flag.Bool("enroll", false, "one-shot: redeem a claim code for this node's first device credential, write it into -device-cred-dir, and QUIT (issue #170, ADR-0071). Run it once, before the service; the service itself is never given a claim code, so no restart can present a spent one. Requires -account-service and a non-empty -device-cred-dir. With no claim code it collects instead, which spends nothing and is how a node whose credential file was lost — but whose device key survived — gets a credential back"),
		codeFile: flag.String("claim-code-file", defaultClaimCodeFile, "with -enroll: where to read the claim code from. \"-\" (the default) is stdin, and is the shape to prefer because a code piped in never reaches a disk. A path is read and then UNLINKED once the code has bought a credential; it is left in place on a refusal, because an operator who mistyped needs to see what they typed. Empty asks for nothing and collects a credential for a device key that is already enrolled"),
	}
}

// addresses is the configured account-service address list.
func (f accountFlags) addresses() []string { return splitCSV(*f.service) }

// configured reports whether this deployment names an account service at all.
// Empty is a complete configuration: nothing enrolls, nothing renews, and the
// node behaves exactly as one predating this file.
func (f accountFlags) configured() bool { return len(f.addresses()) > 0 }

// effectiveLabel is what an enrollment tells the account service to call this
// node.
func (f accountFlags) effectiveLabel() string {
	if l := strings.TrimSpace(*f.label); l != "" {
		return l
	}
	return defaultDeviceLabel
}

// newClient builds the account-service client.
//
// Every refusal accountclient.New makes is a value that cannot be defaulted — an
// empty audience binds assertions to nothing, an absent CA falls back to the
// public root pool — so a typo here is fatal at startup rather than a silently
// skipped feature. That is -admission-cred's existing posture in this binary and
// ADR-0056 §5's ruling for the desktop client, applied to the same values.
func (f accountFlags) newClient() (*accountclient.Client, error) {
	return accountclient.New(accountclient.Config{
		BaseURLs:     f.addresses(),
		Audience:     strings.TrimSpace(*f.audience),
		ServerCAFile: strings.TrimSpace(*f.ca),
		Logf:         log.Printf,
	})
}

// errNoCredDir is the refusal both entry points below share, and it is the
// sharpest edge in this file.
//
// -device-cred-dir defaults to EMPTY in this binary, and empty is devicestore's
// documented in-memory mode: a fresh device identity every start, persisted
// nowhere. Enrolling into one would spend a single-use claim code binding a
// credential to a key that ceases to exist when the process does — unrecoverably,
// because the service erases a spent claim hash rather than flagging it. Renewing
// against one is merely inert, which is worse in a different way: it looks
// configured.
//
// clients/fyne cannot reach this failure because its deviceCredDir defaults to a
// per-user directory. This binary's default is the opposite, so the check lives
// here.
var errNoCredDir = errors.New("-account-service needs a -device-cred-dir to keep the credential in: " +
	"an empty -device-cred-dir is an in-memory device identity that is regenerated on every start, " +
	"so a credential enrolled into it is lost with the process and a claim code spent on it cannot be spent again")

// runEnrollment is the -enroll one-shot: obtain this node's device credential and
// return. main exits afterwards; nothing here starts an engine.
//
// It is idempotent in the direction that matters. A node that already holds a
// credential is reported and left alone, spending nothing — because the check
// that must happen before a claim code is spent is "does this device already
// have one", and a provisioning script that runs this twice must not be able to
// destroy a code by doing so.
func runEnrollment(ctx context.Context, f accountFlags, deviceCredDir string) error {
	if !f.configured() {
		return errors.New("-enroll needs -account-service (and its -account-service-audience and -account-service-ca): there is nothing to enroll against")
	}
	dir := strings.TrimSpace(deviceCredDir)
	if dir == "" {
		return errNoCredDir
	}
	cl, err := f.newClient()
	if err != nil {
		return err
	}
	dev, err := core.OpenDeviceEnrollment(dir)
	if err != nil {
		return err
	}
	if dev.Enrolled() {
		// Nothing is spent and nothing is asked of the service. Reported as
		// success: the operator wanted this node to hold a credential and it
		// does.
		log.Printf("enrollment: this node already holds a device credential in %s%s — nothing to do", dir, expirySuffix(dev))
		return nil
	}

	claim, source, err := readClaimCode(*f.codeFile)
	if err != nil {
		return err
	}

	if claim == "" {
		// Collect: /v1/credential with the device key alone. It spends no claim
		// code and is safe to repeat, and it is the path for a node whose
		// credential file was lost while its device key survived — a real
		// outcome here, because core/devicestore soft-fails an unreadable
		// credential to empty (ADR-0046 §4) and the engine's renewal loop
		// deliberately does not treat an empty store as a reason to enroll.
		if _, err := cl.Collect(ctx, dev); err != nil {
			return fmt.Errorf("could not collect a credential for this node's device key: %w "+
				"(if this device was never enrolled, supply a claim code with -claim-code-file)", err)
		}
		log.Printf("enrollment: this node now holds a device credential in %s%s (collected — no claim code was spent)", dir, expirySuffix(dev))
		return nil
	}

	_, err = cl.Enroll(ctx, dev, claim, f.effectiveLabel())
	switch {
	case err == nil, errors.Is(err, accountclient.ErrAlreadyHaveCredential):
		// The code is spent. Remove the file that held it before anything else
		// reports success, and shout if that fails: a spent bearer secret left
		// readable on a server is the one failure this whole flow exists to
		// prevent, and it is invisible unless it is said.
		source.consume()
		log.Printf("enrollment: this node now holds a device credential in %s%s", dir, expirySuffix(dev))
		return nil

	case accountclient.Terminal(err):
		// The same answer in ten seconds and in ten hours. The file stays: an
		// operator who mistyped needs to see and correct what they typed.
		return fmt.Errorf("the account service refused to enroll this node: %w", err)

	default:
		// Unreachable, rate limited, or the service failed. The claim code MAY
		// have been spent by a request whose reply was lost, and Enroll has
		// already tried the one recovery that exists. Say what a second attempt
		// will look like so the operator is not surprised by claim_rejected.
		return fmt.Errorf("could not enroll this node: %w\n"+
			"the claim code may already have been spent — if a retry answers claim_rejected, "+
			"run -enroll with -claim-code-file= (empty) to collect the credential it bought", err)
	}
}

// claimSource is where a claim code came from, and what to do with it once it
// has been spent. It exists so the consume step is decided where the code is
// read rather than re-derived where it is spent.
type claimSource struct{ path string }

// consume removes the file a claim code was read from. Nothing to do for stdin,
// which is the reason stdin is the default: a code that never reached a disk
// needs no erasure and cannot fail to be erased.
//
// Unlink, not overwrite. Rewriting the bytes in place is not an erase on a
// journaling or copy-on-write filesystem, and doing it anyway would buy a
// feeling rather than a property.
func (s claimSource) consume() {
	if s.path == "" {
		return
	}
	if err := os.Remove(s.path); err != nil {
		log.Printf("WARNING: the claim code in %s has been SPENT but the file could not be removed: %v — "+
			"delete it yourself; it is a bearer secret and it is now worthless to you and not to anyone who reads it", s.path, err)
		return
	}
	log.Printf("enrollment: removed the spent claim code at %s", s.path)
}

// readClaimCode reads the claim code named by -claim-code-file.
//
//	"-"    stdin, which is the shape to prefer
//	""     nothing: collect rather than enroll
//	path   a file, removed by claimSource.consume once the code is spent
//
// An empty file or an empty stdin is an ERROR rather than a fallback to
// collecting. The operator named a source; a source that turned out to hold
// nothing is a mistake to report, not a different intention to infer.
func readClaimCode(spec string) (string, claimSource, error) {
	switch strings.TrimSpace(spec) {
	case "":
		return "", claimSource{}, nil
	case "-":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", claimSource{}, fmt.Errorf("read the claim code from stdin: %w", err)
		}
		code := strings.TrimSpace(string(b))
		if code == "" {
			return "", claimSource{}, errors.New("no claim code on stdin: pipe one in, name a file with -claim-code-file, or pass -claim-code-file= (empty) to collect a credential without spending a code")
		}
		return code, claimSource{}, nil
	default:
		path := strings.TrimSpace(spec)
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
			// Said before the code is used, because after it is spent the
			// warning is about a file that no longer exists.
			log.Printf("WARNING: the claim code at %s is readable by more than its owner (mode %04o) — it is a bearer secret", path, fi.Mode().Perm())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", claimSource{}, fmt.Errorf("read the claim code: %w", err)
		}
		code := strings.TrimSpace(string(b))
		if code == "" {
			return "", claimSource{}, fmt.Errorf("the claim code file %s is empty", path)
		}
		return code, claimSource{path: path}, nil
	}
}

// expirySuffix reports when what this device now holds claims to expire, for a
// log line. Empty when there is nothing to read — a credential this node cannot
// decode is still a credential a coordinator may admit, so this never fails an
// operation, it just says less.
func expirySuffix(dev *core.DeviceEnrollment) string {
	cred, ok := dev.Current()
	if !ok {
		return ""
	}
	exp, ok := devicestore.Expiry(cred.Device)
	if !ok {
		return ""
	}
	return fmt.Sprintf(", valid until %s", exp.UTC().Format(time.RFC3339))
}

// defaultClaimCodeFile is -claim-code-file's default, and the check below turns
// on it: a value that differs from it was typed by an operator.
const defaultClaimCodeFile = "-"

// setupAccountService is what a RUNNING node does about the account service:
// nothing at all when none is configured, and otherwise fill
// core.Config.DeviceRenew — the seam ADR-0046 kept and only clients/fyne has ever
// filled. Nil is renewal off: the pre-#170 posture exactly.
//
// ADR-0046's amendment ruled that "whatever ships enrollment should ship renewal
// with it: one change, one protocol, one place a user configures it", and this is
// the second half of that. The one place is -account-service; the protocol is the
// same core/accountclient the desktop client speaks; and a node that enrolls and
// cannot renew would go dark at its credential's expiry having done everything
// asked of it.
//
// roles decides only whether to WARN. The engine starts its renewal loop for the
// client role alone (core/engine.go), because a device credential is presented at
// connect and a pure forwarder never connects — so an account service configured
// on an exit-only node is inert, and inert-but-configured is the state worth
// naming out loud.
//
// It also refuses a -claim-code-file on a start that is not -enroll. That flag is
// read by the one-shot and by nothing else, so a unit file carrying it describes
// an enrollment that will never happen — an operator would have provisioned a
// claim code, watched the node start cleanly, and found out at the first
// gate-enabled connect. A flag that is silently inert is the failure this whole
// file is about, one level up.
func setupAccountService(f accountFlags, deviceCredDir string, roles []string) (func(context.Context, core.DeviceRenewRequest) (devicestore.Credential, error), error) {
	if strings.TrimSpace(*f.codeFile) != defaultClaimCodeFile {
		return nil, errors.New("-claim-code-file is read only by -enroll, and this start is not one: " +
			"enroll first with `bacchus-node -enroll -claim-code-file=… -device-cred-dir=…`, then start the service without it")
	}
	if !f.configured() {
		return nil, nil
	}
	if strings.TrimSpace(deviceCredDir) == "" {
		return nil, errNoCredDir
	}
	cl, err := f.newClient()
	if err != nil {
		return nil, err
	}
	if !slices.Contains(roles, core.RoleClient) {
		log.Printf("warning: -account-service is configured but -role does not include client, so this node presents and renews no device credential — the device-credential gate applies to connecting, not to forwarding")
	}
	return func(ctx context.Context, req core.DeviceRenewRequest) (devicestore.Credential, error) {
		fresh, err := cl.Renew(ctx, req)
		if err != nil {
			log.Printf("device credential: %s", renewalFailureText(req.Current.Device, err, time.Now()))
			return devicestore.Credential{}, err
		}
		if exp, ok := devicestore.Expiry(fresh.Device); ok {
			log.Printf("device credential: renewed, valid until %s", exp.UTC().Format(time.RFC3339))
		} else {
			log.Printf("device credential: renewed")
		}
		return fresh, nil
	}, nil
}

// renewalEscalation is when a failing renewal stops being a note and becomes a
// warning, and it is deliberately far larger than the engine's own renewal
// margin.
//
// That margin is when a node STARTS trying; at the service's defaults a
// credential lives 48 hours and renewal begins 6 hours out, so a node that cannot
// reach the service has roughly six hours of ten-minute retries before it goes
// dark. Waiting until the last of those would put the warning inside the window
// where the operator can no longer do anything with it. Half the slack is the
// line, which is ADR-0056 §6's threshold for the same reason.
const renewalEscalation = 3 * time.Hour

// renewalFailureText is what a failed renewal looks like to an operator rather
// than to a stack trace — ADR-0046's fourth question, answered for a daemon whose
// only surface is a log.
//
// It escalates on the CLOCK rather than on what went wrong, because what went
// wrong is mostly not actionable and how much time is left always is. At the
// moment a renewal fails nothing is broken: the node keeps connecting on the
// credential it holds, and it stays fine right up until that credential expires
// and a gate-enabled coordinator starts refusing every connect for a reason
// nobody can connect back to a service outage they never saw.
//
// Two refusals ignore the clock and say so at once, because no amount of waiting
// fixes them.
func renewalFailureText(current string, err error, now time.Time) string {
	if code, ok := accountclient.CodeOf(err); ok {
		switch code {
		case accountclient.CodeEntitlementExpired:
			return fmt.Sprintf("this account's subscription has lapsed, so no fresh credential will be issued: %v", err)
		case accountclient.CodeDeviceRevoked:
			return fmt.Sprintf("this device has been REVOKED; it will keep connecting until its current credential expires and then stop: %v", err)
		}
	}
	exp, ok := devicestore.Expiry(current)
	switch {
	case !ok:
		return fmt.Sprintf("renewal failed and this node's current credential cannot be read, so there is no telling how long it lasts: %v", err)
	case !exp.After(now):
		return fmt.Sprintf("renewal failed and this node's credential EXPIRED at %s — a coordinator with its device gate on is now refusing this node: %v",
			exp.UTC().Format(time.RFC3339), err)
	case exp.Sub(now) <= renewalEscalation:
		return fmt.Sprintf("WARNING: renewal is failing and this node's credential expires at %s, in about %s — after that a coordinator with its device gate on will refuse it: %v",
			exp.UTC().Format(time.RFC3339), coarse(exp.Sub(now)), err)
	default:
		return fmt.Sprintf("renewal failed and will be retried; this node keeps connecting on the credential it holds, which is valid until %s (about %s): %v",
			exp.UTC().Format(time.RFC3339), coarse(exp.Sub(now)), err)
	}
}

// coarse renders a remaining lifetime the way an operator reads one. Minutes
// under an hour, whole hours above it: a credential with 4h37m left has four
// hours left, and the extra precision would only suggest the number means more
// than it does.
func coarse(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Round(time.Minute).Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
