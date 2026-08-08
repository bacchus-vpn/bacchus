// admission-issue is the operator-side authority for cryptographic node
// admission (issue #42). It mints signed credentials that clients and nodes
// present to the coordinator, and manages the revocation list. It holds the
// admission root private key — the trust anchor whose public half is configured
// into the coordinator (-admission-pubkey) — so it is run offline / on the
// issuing machine, never on a serving node.
//
// Typical use:
//
//	# first run generates the root key and prints the public key to configure
//	# the coordinator with; issue a 30-day exit-node credential bound to a node id:
//	admission-issue -subject <exit-x25519-pubkey-hex> -roles exit -ttl 720h > exit.cred
//
//	# a client credential (bearer; not bound to an id), handed out of band:
//	admission-issue -subject alice -roles client -ttl 2160h > alice.cred
//
//	# revoke a leaked credential by its serial (hot-reloaded by the coordinator):
//	admission-issue -revoke 1a2b3c4d5e6f7788
//
//	# sign the current revocation list as a short-lived bundle for clients
//	# (issue #69) — feed the result to cmd/coldstart-issue -admission-crl or a
//	# node's -admission-crl, and re-run this periodically before it lapses:
//	admission-issue -crl -crl-ttl 24h > revocations.crl
//
// The credential is printed to stdout (pipe it to a file); diagnostics go to
// stderr. A client credential travels to its recipient out of band, exactly
// like a coldstart invite (cmd/coldstart-issue): the channel it rides is its
// integrity, and it carries no secret to forge.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/atomicfile"
)

func main() {
	keyPath := flag.String("key", "secrets/admission-root.key", "admission root ed25519 signing key (hex seed); generated on first run if missing")
	subject := flag.String("subject", "", "subject the credential is bound to: a node id (an exit's X25519 public key) for relay/exit, or any user label for a client")
	rolesArg := flag.String("roles", "", "comma list of roles to authorize: client,relay,exit")
	ttl := flag.Duration("ttl", 720*time.Hour, "validity window length from -not-before (e.g. 720h = 30 days)")
	notBeforeArg := flag.String("not-before", "", "RFC3339 start of validity (default: now)")
	note := flag.String("note", "", "free-form operator label recorded in the credential (e.g. who it was issued to); not security-relevant")
	printPub := flag.Bool("pubkey", false, "print the admission public key (for the coordinator's -admission-pubkey) and exit")
	revoke := flag.String("revoke", "", "revoke this credential serial instead of issuing: add it to -revocations and exit")
	revocationsPath := flag.String("revocations", "secrets/admission-revocations.json", "revocation file to append to with -revoke, or to sign with -crl")
	crlMode := flag.Bool("crl", false, "sign -revocations as a short-lived bundle instead of issuing a credential (issue #69); distribute it alongside the admission anchor (e.g. cmd/coldstart-issue -admission-crl) so a client can reject a revoked exit before it naturally expires")
	crlTTL := flag.Duration("crl-ttl", 24*time.Hour, "validity window for -crl; short-lived by design — the recipient must be handed a fresh one before it lapses")
	flag.Parse()

	priv, err := loadOrGenerateAdmissionKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	switch {
	case *printPub:
		fmt.Println(hex.EncodeToString(pub))
	case *revoke != "":
		if err := revokeSerial(*revocationsPath, *revoke); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "revoked serial %s in %s\n", *revoke, *revocationsPath)
	case *crlMode:
		if err := emitCRL(priv, *revocationsPath, *crlTTL); err != nil {
			log.Fatal(err)
		}
	default:
		if err := issue(priv, *subject, *rolesArg, *notBeforeArg, *ttl, *note); err != nil {
			log.Fatal(err)
		}
	}
}

// issue mints and prints one credential. The encoded string goes to stdout so
// it can be redirected to a file; a human-readable summary goes to stderr.
func issue(priv ed25519.PrivateKey, subject, rolesArg, notBeforeArg string, ttl time.Duration, note string) error {
	if subject == "" {
		return errors.New("need -subject (a node id for relay/exit, or a user label for client)")
	}
	roles, err := parseRoles(rolesArg)
	if err != nil {
		return err
	}
	notBefore := time.Now()
	if notBeforeArg != "" {
		notBefore, err = time.Parse(time.RFC3339, notBeforeArg)
		if err != nil {
			return fmt.Errorf("bad -not-before: %w", err)
		}
	}
	notAfter := notBefore.Add(ttl)

	c, encoded, err := admission.Issue(priv, subject, roles, notBefore, notAfter, note)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "issued credential: serial=%s subject=%q roles=%s valid=[%s .. %s]\n",
		c.Serial, c.Subject, rolesArg, notBefore.UTC().Format(time.RFC3339), notAfter.UTC().Format(time.RFC3339))
	fmt.Println(encoded)
	return nil
}

// parseRoles turns the comma list into validated admission roles, rejecting
// anything that is not a known role so a typo can't mint a useless credential.
func parseRoles(s string) ([]admission.Role, error) {
	var roles []admission.Role
	for _, r := range strings.Split(s, ",") {
		switch admission.Role(strings.TrimSpace(r)) {
		case admission.RoleClient:
			roles = append(roles, admission.RoleClient)
		case admission.RoleRelay:
			roles = append(roles, admission.RoleRelay)
		case admission.RoleExit:
			roles = append(roles, admission.RoleExit)
		case "":
			// tolerate stray commas / whitespace
		default:
			return nil, fmt.Errorf("unknown role %q in -roles (want client,relay,exit)", strings.TrimSpace(r))
		}
	}
	if len(roles) == 0 {
		return nil, errors.New("need -roles (comma list of client,relay,exit)")
	}
	return roles, nil
}

// revokeSerial adds serial to the revocation file, creating it if missing and
// preserving any serials already there.
func revokeSerial(path, serial string) error {
	rl, err := admission.LoadRevocationList(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		rl = admission.NewRevocationList()
	}
	rl.Revoke(serial)
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	return rl.SaveFile(path)
}

// emitCRL signs the current contents of the revocations file as a short-TTL
// bundle (issue #69) and prints it to stdout; diagnostics go to stderr,
// mirroring issue. A missing file signs an empty bundle rather than erroring
// — a freshly-signed "nothing revoked as of now" attestation is meaningful
// too, and is exactly what an operator with no revocations yet should be able
// to distribute.
func emitCRL(priv ed25519.PrivateKey, revocationsPath string, ttl time.Duration) error {
	rl, err := admission.LoadRevocationList(revocationsPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		rl = admission.NewRevocationList()
	}
	serials := rl.Serials()
	now := time.Now()
	encoded, err := admission.SignCRL(priv, serials, now, ttl)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "issued CRL: %d revoked serial(s), valid=[%s .. %s]\n",
		len(serials), now.UTC().Format(time.RFC3339), now.Add(ttl).UTC().Format(time.RFC3339))
	fmt.Println(encoded)
	return nil
}

// loadOrGenerateAdmissionKey reads the hex-encoded ed25519 seed at path, or
// generates and persists a new keypair if the file doesn't exist. On
// generation it prints the public key to stderr — this is the value the
// operator configures into the coordinator as -admission-pubkey. Mirrors the
// coordinator's bootstrap-key handling so the two operator keys are managed the
// same way.
//
// The create is O_EXCL and the seed is flushed before this returns; bacchus#189
// is both. This is a CLI, so it is the one of the three seed writers an operator
// can reasonably run in parallel — `xargs -P` over a batch against a fresh -key
// path — and read-then-create is a TOCTOU: without O_EXCL two invocations both
// see no file, both generate a ROOT SIGNING KEY, and the loser's is overwritten
// with no error, after which whatever it signed verifies against nothing anybody
// holds. EEXIST refuses rather than re-reading, because the key this process
// holds in memory is not the key on disk. The flush is because the line below
// puts the public half in front of an operator to paste into a coordinator; an
// unclean shutdown before the bytes reach the platter leaves that pubkey
// distributed and its private half gone.
//
// The DIRECTORY entry is flushed for the same reason and is #215's half of it
// (ADR-0066 §5/§6). A file's own Sync makes the bytes durable and commits
// nothing about the entry naming them, so a power loss straight after a first
// run can come back with NO key file — and the branch above then reads that as a
// cold start and mints a second ROOT SIGNING KEY, silently, after the first
// one's public half has already been pasted into a coordinator. A first-run
// create is the definition of a write nothing re-emits, and it cannot go through
// atomicfile.Write because O_EXCL on the real path is the whole point;
// atomicfile.SyncDir is exported for exactly this.
//
// A partial write is left where it lies: a short file is refused loudly by the
// malformed-key branch above on the next run, whereas removing it would present
// the next run with a missing file and mint a second root key silently.
func loadOrGenerateAdmissionKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("malformed admission key at %s", path)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read admission key %s: %w", path, err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate admission key: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("admission key %s was created by another process while this one was generating: "+
				"refusing, because the key this run holds is not the key on disk", path)
		}
		return nil, fmt.Errorf("create admission key %s: %w", path, err)
	}
	if _, err := f.WriteString(hex.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return nil, fmt.Errorf("write admission key %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("flush admission key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close admission key %s: %w", path, err)
	}
	// Before the two lines below, deliberately: they are what puts this key's
	// public half in front of an operator to paste into a coordinator, and a
	// directory whose entry could not be flushed is exactly the case in which
	// that pubkey must not be advertised. The key file is on disk either way, so
	// re-running reads it rather than minting a second root.
	if err := atomicfile.SyncDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("flush the directory holding %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "admission: generated new root signing key at %s\n", path)
	fmt.Fprintf(os.Stderr, "admission: configure the coordinator with -admission-pubkey %s\n", hex.EncodeToString(pub))
	return priv, nil
}
