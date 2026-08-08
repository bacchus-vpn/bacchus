package devicestore

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// fakeCredential builds a syntactically valid "bacchusd1:" envelope carrying the
// given expiry, with a 64-byte trailing signature Expiry never checks (it only
// ever looks at the body). It exists to test Expiry/NeedsRenewal in isolation,
// without minting a whole issuer-cert/root chain a scheduling-only reader has no
// business verifying anyway.
func fakeCredential(t *testing.T, notAfter time.Time) string {
	t.Helper()
	body, err := json.Marshal(struct {
		V         int       `json:"v"`
		Serial    string    `json:"serial"`
		DevicePub []byte    `json:"dpub"`
		Epoch     uint64    `json:"epoch"`
		NotBefore time.Time `json:"nbf"`
		NotAfter  time.Time `json:"exp"`
	}{V: 1, Serial: "test", DevicePub: make([]byte, ed25519.PublicKeySize), NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter})
	if err != nil {
		t.Fatalf("marshal fake credential body: %v", err)
	}
	signed := append(body, make([]byte, ed25519.SignatureSize)...)
	return devicecred.EncodeDeviceCredential(signed)
}

func TestStore_OpenEmptyPathIsInMemoryOnly(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := s.Get(); ok {
		t.Fatal("a fresh store must report ok=false")
	}
	want := Credential{Device: "cred", IssuerCert: "cert", Admission: "adm"}
	if err := s.Put(want); err != nil {
		t.Fatalf("Put on an in-memory store must not error: %v", err)
	}
	got, ok := s.Get()
	if !ok || got != want {
		t.Fatalf("Get after Put = (%+v, %v), want (%+v, true)", got, ok, want)
	}
}

func TestStore_OpenMissingFileIsEmpty(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "nope", "credential.json"))
	if err != nil {
		t.Fatalf("Open on a missing file must not error: %v", err)
	}
	if _, ok := s.Get(); ok {
		t.Fatal("expected an empty store")
	}
}

func TestStore_OpenCorruptFileIsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("a damaged credential cache must never stop a client connecting, got error: %v", err)
	}
	if _, ok := s.Get(); ok {
		t.Fatal("expected an empty store from a corrupt file")
	}
}

func TestStore_PutPersistsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device", "credential.json")
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := Credential{Device: "bacchusd1:cred", IssuerCert: "bacchusi1:cert", Admission: "bacchusc1:adm"}
	if err := s1.Put(want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat persisted file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file perm = %o, want 0600", perm)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	got, ok := s2.Get()
	if !ok || got != want {
		t.Fatalf("Get after re-Open = (%+v, %v), want (%+v, true) — all three survive a restart together", got, ok, want)
	}
}

func TestStore_GetIsFalseOnPartialPair(t *testing.T) {
	s, _ := Open("")
	if err := s.Put(Credential{Device: "cred-only"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := s.Get(); ok {
		t.Fatal("a credential with no issuer cert is not presentable and must report ok=false")
	}

	// An admission credential does not make a partial pair presentable, and its
	// absence does not make a whole one unpresentable: it answers a different
	// gate under a different authority, so it is not part of this question.
	if err := s.Put(Credential{Device: "cred-only", Admission: "bacchusc1:adm"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := s.Get(); ok {
		t.Fatal("an admission credential must not make a missing issuer cert presentable")
	}
	if err := s.Put(Credential{Device: "d", IssuerCert: "i"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := s.Get(); !ok {
		t.Fatal("a deployment that mints no admission credential still has a presentable device credential")
	}
}

// TestStore_OpenReadsAPreAdmissionRecord pins that widening the record did not
// break the files already on disk. The two original keys keep their names, so a
// credential written before the admission credential had a slot still loads —
// with an empty Admission, which is exactly what such a device holds.
func TestStore_OpenReadsAPreAdmissionRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(path, []byte(`{"cred":"bacchusd1:old","issuerCert":"bacchusi1:old"}`), 0o600); err != nil {
		t.Fatalf("seed pre-#166 file: %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, ok := s.Get()
	if !ok || got.Device != "bacchusd1:old" || got.IssuerCert != "bacchusi1:old" {
		t.Fatalf("Get = (%+v, %v), want the two persisted strings", got, ok)
	}
	if got.Admission != "" {
		t.Fatalf("Admission = %q, want empty from a record that has no such field", got.Admission)
	}
}

// TestStore_OpenAdoptsALegacyAdmissionFile covers the one upgrade that would
// otherwise reproduce the exact defect this store's third field exists to fix: a
// device enrolled between bacchus#163 and bacchus#166 keeps its admission
// credential in a file of its own, and reading only the JSON would silently
// leave that device off an admission-enforcing network until its next renewal.
func TestStore_OpenAdoptsALegacyAdmissionFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(path, []byte(`{"cred":"bacchusd1:old","issuerCert":"bacchusi1:old"}`), 0o600); err != nil {
		t.Fatalf("seed pre-#166 file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, legacyAdmissionFileName), []byte("bacchusc1:legacy\n"), 0o600); err != nil {
		t.Fatalf("seed legacy admission file: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, _ := s.Get()
	if got.Admission != "bacchusc1:legacy" {
		t.Fatalf("Admission = %q, want the adopted legacy value (trailing newline trimmed)", got.Admission)
	}

	// Adoption is a read, and the next write folds it in: after one Put the
	// record carries all three and the legacy file is no longer consulted.
	got.Device = "bacchusd1:renewed"
	if err := s.Put(got); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, legacyAdmissionFileName)); err != nil {
		t.Fatalf("remove legacy file: %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	if again, _ := s2.Get(); again != got {
		t.Fatalf("Get after re-Open = %+v, want %+v — the adopted value must be in the record, not still in the file", again, got)
	}
}

// TestStore_OpenIgnoresAnUnusableLegacyAdmissionFile is the soft-fail half: a
// half-written or empty legacy file must read as "no admission credential",
// never as a torn one this device would go on presenting.
func TestStore_OpenIgnoresAnUnusableLegacyAdmissionFile(t *testing.T) {
	for _, contents := range []string{"", "   \n", "bacchusc1:one\nbacchusc1:two\n"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "credential.json")
		if err := os.WriteFile(path, []byte(`{"cred":"d","issuerCert":"i"}`), 0o600); err != nil {
			t.Fatalf("seed record: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, legacyAdmissionFileName), []byte(contents), 0o600); err != nil {
			t.Fatalf("seed legacy admission file: %v", err)
		}
		s, err := Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got, _ := s.Get(); got.Admission != "" {
			t.Fatalf("Open adopted %q from a legacy file holding %q, want nothing", got.Admission, contents)
		}
	}
}

// TestStore_RecordKeysAreStable asserts the on-disk key names directly, because
// nothing else can. Renaming one is invisible to every other test here — Put and
// Open would agree with each other about the new name — and shows up only as a
// device that silently forgot its credential after an upgrade.
func TestStore_RecordKeysAreStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Put(Credential{Device: "d", IssuerCert: "i", Admission: "a"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("persisted file is not a flat string map: %v", err)
	}
	want := map[string]string{"cred": "d", "issuerCert": "i", "admission": "a"}
	if len(raw) != len(want) {
		t.Fatalf("persisted record = %v, want exactly %v", raw, want)
	}
	for k, v := range want {
		if raw[k] != v {
			t.Fatalf("persisted record[%q] = %q, want %q (full record %v)", k, raw[k], v, raw)
		}
	}

	// omitempty on the new key only: a deployment that mints no admission
	// credential writes the same two-key file it always did.
	if err := s.Put(Credential{Device: "d", IssuerCert: "i"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	// A fresh map: json.Unmarshal MERGES into a non-nil one, so reusing the
	// previous map would leave the old "admission" key behind and this assertion
	// would be about the test rather than about the file.
	raw = nil
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("persisted file is not a flat string map: %v", err)
	}
	if _, present := raw["admission"]; present {
		t.Fatalf("an empty admission credential was written out as %v, want the key omitted", raw)
	}
}

func TestExpiry_ReadsClaimedNotAfter(t *testing.T) {
	want := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	got, ok := Expiry(fakeCredential(t, want))
	if !ok {
		t.Fatal("expected Expiry to decode the fake credential")
	}
	if !got.Equal(want) {
		t.Fatalf("Expiry = %v, want %v", got, want)
	}
}

func TestExpiry_FalseOnMalformedEnvelope(t *testing.T) {
	for _, s := range []string{"", "not-an-envelope", "bacchusd1:not-base64!!"} {
		if _, ok := Expiry(s); ok {
			t.Fatalf("Expiry(%q) reported ok=true, want false", s)
		}
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	margin := 6 * time.Hour

	cases := []struct {
		name string
		cred string
		want bool
	}{
		{"unknown expiry -> due", "garbage", true},
		{"far from expiry -> not due", fakeCredential(t, now.Add(48*time.Hour)), false},
		{"inside margin -> due", fakeCredential(t, now.Add(3*time.Hour)), true},
		{"already expired -> due", fakeCredential(t, now.Add(-time.Hour)), true},
		{"exactly at margin boundary -> due", fakeCredential(t, now.Add(margin)), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NeedsRenewal(c.cred, now, margin); got != c.want {
				t.Fatalf("NeedsRenewal = %v, want %v", got, c.want)
			}
		})
	}
}

// Issue #188: this store used to stage under a FIXED name (path + ".tmp"). A
// second saver of the same file staged into that same file, and whichever
// rename ran last installed a mixture of the two.
//
// Asserted without a race, because the property is structural rather than
// statistical: a file sitting at the old staged name is now UNTOUCHED by a
// save. Under the old writer that file WAS the staging area — it would have
// been truncated, refilled and renamed away.
func TestStore_PutDoesNotStageUnderThePredictableName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	squatter := path + ".tmp"
	if err := os.WriteFile(squatter, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Put(Credential{Device: "bacchusd1:cred", IssuerCert: "bacchusi1:cert"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	b, err := os.ReadFile(squatter)
	if err != nil {
		t.Fatalf("the save consumed %s, so it is still staging under a name another saver can pick: %v", squatter, err)
	}
	if string(b) != "not ours" {
		t.Errorf("%s now holds %q; a save must stage under a name it created itself", squatter, b)
	}
}

// The same defect from the other side: two savers of one file, concurrently,
// and every state the file is ever observed in has to be one saver's whole
// record. A mixture parses as garbage and Open soft-fails it to empty, which is
// this store silently forgetting a credential it was told to persist.
func TestStore_ConcurrentSaversNeverInstallAMixture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")

	// Two stores at one path is what two client processes sharing a state
	// directory are. Their in-memory halves are independent by construction;
	// the file is the only thing they share.
	creds := []Credential{
		{Device: "bacchusd1:" + strings.Repeat("A", 400), IssuerCert: "bacchusi1:" + strings.Repeat("a", 900), Admission: "bacchusc1:" + strings.Repeat("1", 300)},
		{Device: "bacchusd1:" + strings.Repeat("B", 700), IssuerCert: "bacchusi1:" + strings.Repeat("b", 200)},
	}

	var writers, readers sync.WaitGroup
	stop := make(chan struct{})
	var reads atomic.Int64

	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(path)
			if err != nil || len(b) == 0 {
				continue
			}
			var rec record
			if err := json.Unmarshal(b, &rec); err != nil {
				t.Errorf("a reader observed %d bytes of unparseable JSON: %v — two savers interleaved into one staged file", len(b), err)
				return
			}
			got := Credential{Device: rec.Cred, IssuerCert: rec.IssuerCert, Admission: rec.Admission}
			if got != creds[0] && got != creds[1] {
				t.Errorf("a reader observed a credential no saver wrote: %+v", got)
				return
			}
			reads.Add(1)
		}
	}()

	for i := range creds {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			s, err := Open(path)
			if err != nil {
				t.Errorf("Open: %v", err)
				return
			}
			for n := 0; n < 60; n++ {
				if err := s.Put(creds[i]); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
			}
		}(i)
	}
	writers.Wait()
	close(stop)
	readers.Wait()

	if reads.Load() == 0 {
		t.Error("no reader ever observed the file; this test proved nothing")
	}
}
