package accountclient

import (
	"os"
	"path/filepath"
	"strings"
)

// admissionFileName is where a device's admission credential lives, inside the
// same directory core.OpenDeviceEnrollment keeps the device key and the device
// credential in.
//
// It is a file of this package's own because core/devicestore holds exactly two
// strings — the device credential and the issuer cert — and this is a third,
// under a different authority, answering a different question. Widening that
// store to three would change a signature core owns, and this lane does not own
// it; see ADR-0056 §7, which proposes exactly that change and says why it is
// proposed rather than made.
//
// It sits beside them rather than somewhere of its own because these three files
// are one device's identity and lose their meaning apart: an admission
// credential names the device public key that lives in the same directory, so a
// user who moves or deletes the directory should take or lose all of it
// together, not two thirds of it.
const admissionFileName = "admission.cred"

// AdmissionPath is where dir keeps the admission credential, or "" when dir is
// empty (an in-memory enrollment, which persists nothing).
func AdmissionPath(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, admissionFileName)
}

// LoadAdmission reads the admission credential stored in dir, or returns "" when
// there is none.
//
// It SOFT-FAILS to empty on every failure — missing file, unreadable file,
// garbage contents — matching core/devicestore.Open's posture rather than the
// device key's. The two postures differ for a reason and this one belongs on
// this side of the line: an admission credential is a short-lived, reissuable
// grant, not an identity, so losing it costs membership until the next renewal
// rather than orphaning anything. Refusing to start over it would make a damaged
// cache the reason a client cannot even try to connect.
//
// Nothing here verifies it. This client holds no admission anchor and has no
// business holding one: the credential is opaque to its bearer and meaningful
// only to the coordinator that checks it.
func LoadAdmission(dir string) string {
	p := AdmissionPath(dir)
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	// A single line, and nothing that is not one. The envelope form has no
	// whitespace in it, so anything multi-line here is a file that was written
	// by something else or half-written by something that crashed.
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return ""
	}
	return s
}

// saveAdmission writes cred into dir, atomically.
//
// Atomic because the reader is a client about to connect and the writer is a
// renewal running on a timer: a torn file is an unusable credential presented in
// place of a usable one, and rename-into-place makes that state unrepresentable
// rather than rare. Written 0600 in a directory core/devicestore already creates
// 0700 — the file next to it holds this device's private key, so nothing here
// widens what that directory is worth reading.
func saveAdmission(dir, cred string) error {
	p := AdmissionPath(dir)
	if p == "" {
		return nil // in-memory enrollment: nothing persists, by the caller's choice
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, admissionFileName+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(cred); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}
