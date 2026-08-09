// Command release-sign authors, signs and verifies a Bacchus release manifest.
//
// # This runs OFFLINE, on the air-gapped machine that holds the update key
//
// ADR-0052 §6 is explicit and this tool exists to make it followable: the update
// signing key never sits on a coordinator, never on a build machine, and CI NEVER
// HOLDS IT. A build machine that can sign is a build machine that can push code to
// every node, which is the compromise ADR-0015 calls the highest-value attack
// surface in the system. Signing is therefore a separate, deliberate act performed
// on artifacts CI produced, not a step inside the pipeline that produced them.
//
// Nothing here opens a network connection, and nothing here reaches a workflow
// file. If a CI job ever needs this binary, something has gone wrong upstream of
// this comment.
//
// # The five-step release procedure it implements (ADR-0052 §6)
//
//  1. CI produces the artifacts. It signs nothing and holds nothing. The release
//     workflow emits artifacts.json — the rows this tool's `plan` reads.
//  2. The pure-Go fleet binaries are independently rebuilt and confirmed
//     byte-identical to CI's (ADR-0052 §5: -trimpath, CGO_ENABLED=0, a pinned
//     toolchain). The GUI cannot be, so its hash is taken from one designated build.
//  3. The manifest is authored offline:
//     release-sign plan -from artifacts.json -release 1.2.3 -seq 7 -out body.json
//  4. It is signed under the update delegation:
//     release-sign sign -body body.json -key update.key -cert update.cert -root <hex> -out manifest.json
//  5. The signed manifest is published beside the blobs, and the coordinator
//     announces the release.
//
// Step 4 refuses if the delegation cert does not verify against the root for the
// UPDATE role, or if it does not delegate to the key being signed with. Both are
// mistakes that would otherwise produce a perfectly formed release that every
// node in the fleet refuses — discovered after the ceremony, by the fleet.
//
// # Verifying, which anyone can do
//
//	release-sign verify -bundle manifest.json -root <hex> [-dir <source directory>]
//
// With -dir it also checks every blob's bytes against the manifest, which is what
// a mirror operator or an independent rebuilder runs. It needs no key at all: that
// is the property content addressing buys.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
	"github.com/bacchus-vpn/bacchus/core/update"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "plan":
		err = plan(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "keygen":
		err = keygen(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "release-sign: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "release-sign: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `release-sign authors, signs and verifies a Bacchus release manifest.

It runs OFFLINE, on the machine that holds the update signing key. CI never runs
it and never holds that key (ADR-0052 section 6).

  release-sign keygen -out update.key
        Generate an update signing key and print its PUBLIC half, which is what
        the root's ceremony delegates to. Run this on the air-gapped machine.

  release-sign plan -from artifacts.json -release 1.2.3 -seq 7 -out body.json
  release-sign plan -artifact linux/amd64/node=./bacchus-node -release 1.2.3 -seq 7 -out body.json
        Author an unsigned manifest body. -from reads the rows CI produced (the
        offline machine then never needs the artifacts themselves); -artifact
        hashes a file here and may be repeated.

  release-sign sign -body body.json -key update.key -cert update.cert -root <hex> -out manifest.json
        Sign the body verbatim under the update delegation and write the bundle.

  release-sign verify -bundle manifest.json -root <hex> [-dir ./source]
        Verify a bundle against a root, and with -dir every blob's bytes too.
        Needs no key.
`)
}

// ---------------------------------------------------------------- plan

type artifactRow struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Role   string `json:"role"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"` // hex, as every tool that prints digests writes them
}

type artifactList struct {
	Release   string        `json:"release,omitempty"`
	Artifacts []artifactRow `json:"artifacts"`
}

// artifactFlag collects repeated -artifact os/arch/role=path values.
type artifactFlag []string

func (a *artifactFlag) String() string     { return strings.Join(*a, ",") }
func (a *artifactFlag) Set(v string) error { *a = append(*a, v); return nil }

func plan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	var files artifactFlag
	fs.Var(&files, "artifact", "os/arch/role=path, repeatable; the file is hashed here")
	from := fs.String("from", "", "a JSON artifact list produced by the release workflow (rows of os/arch/role/size/sha256)")
	release := fs.String("release", "", "the release version, bare MAJOR.MINOR.PATCH")
	seq := fs.Uint64("seq", 0, "the monotonic manifest sequence; must exceed the last published one")
	days := fs.Int("days", 60, "how long the manifest stays valid, in days")
	issued := fs.String("issued", "", "issue time, RFC3339; empty uses now (UTC)")
	note := fs.String("note", "", "operator label; never load-bearing")
	out := fs.String("out", "", "where to write the unsigned manifest body; empty writes to stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var rows []update.Artifact
	if *from != "" {
		list, err := readArtifactList(*from)
		if err != nil {
			return err
		}
		if *release == "" {
			*release = list.Release
		}
		for _, r := range list.Artifacts {
			a, err := rowToArtifact(r)
			if err != nil {
				return err
			}
			rows = append(rows, a)
		}
	}
	for _, spec := range files {
		a, err := hashArtifact(spec)
		if err != nil {
			return err
		}
		rows = append(rows, a)
	}
	if len(rows) == 0 {
		return errors.New("plan: no artifacts (use -from or -artifact)")
	}
	if *seq == 0 {
		return errors.New("plan: -seq is required and must be at least 1; it must exceed the last published manifest's, or every peer that has seen that one refuses this")
	}
	at := time.Now().UTC()
	if *issued != "" {
		t, err := time.Parse(time.RFC3339, *issued)
		if err != nil {
			return fmt.Errorf("plan: -issued: %w", err)
		}
		at = t.UTC()
	}

	m := update.Manifest{
		Version:   update.Version,
		Seq:       *seq,
		Release:   *release,
		Issued:    at,
		Expires:   at.AddDate(0, 0, *days),
		Note:      *note,
		Artifacts: rows,
	}
	if err := m.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if *out == "" {
		_, err := os.Stdout.Write(body)
		return err
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s: release %s seq %d, %d artifact(s), valid %s to %s\n",
		*out, m.Release, m.Seq, len(m.Artifacts), m.Issued.Format(time.RFC3339), m.Expires.Format(time.RFC3339))
	for _, a := range m.Artifacts {
		fmt.Fprintf(os.Stderr, "  %s/%s %-11s %10d bytes  %s\n", a.OS, a.Arch, a.Role, a.Size, a.Name())
	}
	return nil
}

func readArtifactList(path string) (artifactList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return artifactList{}, err
	}
	var l artifactList
	if err := json.Unmarshal(b, &l); err != nil {
		return artifactList{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(l.Artifacts) == 0 {
		return artifactList{}, fmt.Errorf("%s lists no artifacts", path)
	}
	return l, nil
}

func rowToArtifact(r artifactRow) (update.Artifact, error) {
	sum, err := hex.DecodeString(strings.TrimSpace(r.SHA256))
	if err != nil {
		return update.Artifact{}, fmt.Errorf("artifact %s/%s %s: sha256 is not hex: %w", r.OS, r.Arch, r.Role, err)
	}
	if len(sum) != sha256.Size {
		return update.Artifact{}, fmt.Errorf("artifact %s/%s %s: sha256 is %d bytes", r.OS, r.Arch, r.Role, len(sum))
	}
	return update.Artifact{OS: r.OS, Arch: r.Arch, Role: r.Role, Size: r.Size, SHA256: sum}, nil
}

// hashArtifact reads "os/arch/role=path" and hashes the file at path.
func hashArtifact(spec string) (update.Artifact, error) {
	key, path, ok := strings.Cut(spec, "=")
	if !ok {
		return update.Artifact{}, fmt.Errorf("-artifact %q is not os/arch/role=path", spec)
	}
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		return update.Artifact{}, fmt.Errorf("-artifact %q: the key is os/arch/role", spec)
	}
	f, err := os.Open(path)
	if err != nil {
		return update.Artifact{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return update.Artifact{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return update.Artifact{}, err
	}
	return update.Artifact{OS: parts[0], Arch: parts[1], Role: parts[2], Size: st.Size(), SHA256: h.Sum(nil)}, nil
}

// ---------------------------------------------------------------- sign

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	bodyPath := fs.String("body", "", "the unsigned manifest body from `plan`")
	keyPath := fs.String("key", "", "the update signing key (hex seed, 0600)")
	certPath := fs.String("cert", "", "the update delegation cert minted by the root's ceremony (bacchusg1: string or raw bytes)")
	rootHex := fs.String("root", "", "the root PUBLIC key, hex — the cert is verified against it before anything is signed")
	out := fs.String("out", "", "where to write the signed bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, v := range map[string]string{"-body": *bodyPath, "-key": *keyPath, "-cert": *certPath, "-root": *rootHex, "-out": *out} {
		if v == "" {
			return fmt.Errorf("sign: %s is required", name)
		}
	}

	rootPub, err := update.ParseAnchor(*rootHex)
	if err != nil {
		return err
	}
	// Loud, NOT fatal, and the asymmetry is the point (issue #252).
	//
	// It is tempting to refuse here, since this is where signing authority is
	// exercised. That would be the wrong gate twice over. It would block the only way
	// to exercise the release channel end to end before a real ceremony has run — the
	// rehearsal this warning exists to accompany. And it would guard the artifact that
	// is not actually dangerous: a manifest signed under the development root is INERT
	// against a real build, because that build anchors to the ceremony root and the
	// signature simply does not verify.
	//
	// The thing that cannot be allowed out is a dev-ANCHORED BINARY, because for that
	// binary anyone who can run sha256 over a published sentence is the update
	// authority, and ADR-0052 makes the anchor irrevocable at first ship. That is
	// where the fatal check lives; see the release workflow's anchor gate and
	// TestAReleaseBuildRefusesTheDevelopmentAnchor.
	if update.IsDevRoot(rootPub) {
		fmt.Fprintln(os.Stderr, "release-sign: signing under the DEVELOPMENT root. This release can only ever be applied by a build anchored to the same development root, and both are for exercising the channel. Neither may reach a user (issue #252)")
	}
	priv, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	cert, err := readCert(*certPath)
	if err != nil {
		return err
	}

	// The cert must be live for the UPDATE role against this root, right now.
	// Signing under an expired or wrong-role delegation produces a release every
	// peer refuses, and the ceremony that would fix it is not a five-minute one.
	parsed, err := delegation.VerifyDelegationCert(rootPub, cert, delegation.RoleUpdate, time.Now(), nil)
	if err != nil {
		return fmt.Errorf("sign: the delegation cert is not usable: %w", err)
	}
	// And it must delegate to THIS key. Nothing downstream checks this for us: a
	// manifest signed by a key the cert does not name verifies against nothing, and
	// the failure surfaces on every node at once.
	pub := priv.Public().(ed25519.PublicKey)
	if !pub.Equal(ed25519.PublicKey(parsed.Pub)) {
		return fmt.Errorf("sign: the delegation cert (serial %s) delegates to a different key than %s holds", parsed.Serial, *keyPath)
	}

	body, err := os.ReadFile(*bodyPath)
	if err != nil {
		return err
	}
	signed, err := update.SignBody(priv, body)
	if err != nil {
		return err
	}
	bundle := update.Bundle{Manifest: signed, Cert: cert}
	raw, err := bundle.Marshal()
	if err != nil {
		return err
	}

	// Verify what was just produced, with the same code a node runs, before it is
	// written anywhere. The one moment this is free is now.
	v, err := update.NewVerifier(rootPub, nil)
	if err != nil {
		return err
	}
	m, err := v.Verify(bundle, time.Now(), 0)
	if err != nil {
		return fmt.Errorf("sign: the bundle this just produced does not verify: %w", err)
	}
	if err := os.WriteFile(*out, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s: release %s seq %d under delegation %s (expires %s)\n",
		*out, m.Release, m.Seq, parsed.Serial, parsed.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "publish it as %s beside %s/<digest> for each artifact\n", update.ManifestName, update.BlobDir)
	return nil
}

// readKey reads a 32-byte ed25519 seed in hex and refuses a file anyone but its
// owner can read.
//
// The permission check is not ceremony. This key is the one whose compromise
// ADR-0015 calls a fleet-wide code push, and the cheapest possible mistake — a
// world-readable file on a machine that was air-gapped last week — is worth one
// stat.
func readKey(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if mode := st.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %#o: the update signing key must not be readable by anyone but its owner (chmod 600)", path, mode)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s is not a hex seed: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s holds %d bytes, want a %d-byte ed25519 seed", path, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// readCert accepts either the bacchusg1: string form or the raw signed bytes.
func readCert(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "bacchusg1:") {
		return delegation.DecodeCert(s)
	}
	return b, nil
}

// ---------------------------------------------------------------- verify

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	bundlePath := fs.String("bundle", "", "the signed bundle to check")
	rootHex := fs.String("root", "", "the root PUBLIC key, hex")
	dir := fs.String("dir", "", "a source directory; with it, every blob's bytes are checked against the manifest too")
	at := fs.String("at", "", "verify as of this RFC3339 time instead of now")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" || *rootHex == "" {
		return errors.New("verify: -bundle and -root are required")
	}
	rootPub, err := update.ParseAnchor(*rootHex)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	b, err := update.ParseBundle(raw)
	if err != nil {
		return err
	}
	now := time.Now()
	if *at != "" {
		t, perr := time.Parse(time.RFC3339, *at)
		if perr != nil {
			return fmt.Errorf("verify: -at: %w", perr)
		}
		now = t
	}
	v, err := update.NewVerifier(rootPub, nil)
	if err != nil {
		return err
	}
	m, err := v.Verify(b, now, 0)
	if err != nil {
		return err
	}
	cert, err := delegation.VerifyDelegationCert(rootPub, b.Cert, delegation.RoleUpdate, now, nil)
	if err != nil {
		return err
	}
	fmt.Printf("release %s, seq %d, issued %s, expires %s\n", m.Release, m.Seq, m.Issued.UTC().Format(time.RFC3339), m.Expires.UTC().Format(time.RFC3339))
	fmt.Printf("signed under delegation %s (role %s, expires %s)\n", cert.Serial, cert.Role, cert.NotAfter.UTC().Format(time.RFC3339))
	if m.Note != "" {
		fmt.Printf("note: %s\n", m.Note)
	}
	bad := 0
	for _, a := range m.Artifacts {
		line := fmt.Sprintf("  %s/%s %-11s %10d bytes  %s", a.OS, a.Arch, a.Role, a.Size, a.Name())
		if *dir == "" {
			fmt.Println(line)
			continue
		}
		f, oerr := os.Open(filepath.Join(*dir, update.BlobDir, a.Name()))
		if oerr != nil {
			fmt.Println(line + "  MISSING")
			bad++
			continue
		}
		_, verr := update.VerifyArtifact(a, f)
		f.Close()
		if verr != nil {
			fmt.Println(line + "  FAILS: " + verr.Error())
			bad++
			continue
		}
		fmt.Println(line + "  ok")
	}
	if bad > 0 {
		return fmt.Errorf("verify: %d artifact(s) in %s do not match the manifest", bad, *dir)
	}
	return nil
}

// ---------------------------------------------------------------- keygen

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "where to write the private key (hex seed, mode 0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("keygen: %s already exists; refusing to overwrite a signing key", *out)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	seed := priv.Seed()
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, `wrote %s (mode 0600).

THIS MACHINE SHOULD NOT BE ON A NETWORK. The key just written is the one whose
compromise ADR-0015 calls a fleet-wide code push. It signs manifests only, it
never sits on a coordinator or a build machine, and CI never holds it.

Its own offline medium, separate from the root shares: keeping it beside them
means touching root-share media on every release, which erodes exactly the
property that separation exists to create (ADR-0052 section 6, gate 2).

Hand the PUBLIC key below to the root ceremony, which mints an update-role
delegation for it. Nothing can be signed until that cert exists.

  public key: %s

`, *out, hex.EncodeToString(pub))
	return nil
}
