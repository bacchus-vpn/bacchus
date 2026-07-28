//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSaveConfigRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bacchus.config.json")

	want := Config{
		Coordinators:     []string{"203.0.113.10:51820"}, // TEST-NET-3 (RFC 5737): never a real Bacchus endpoint
		STUN:             "stun:203.0.113.10:3478",
		Geo:              "de",
		ExitID:           "deadbeef",
		TransportPool:    []string{"webrtc", "reality"},
		AdmissionPubKey:  "ababababababababababababababababababababababababababababababab", // placeholder hex-shaped string; round-trip doesn't validate key material
		AdmissionCRLPath: `C:\Bacchus\revocations.crl`,
	}
	if err := saveConfig(path, want); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	// loadConfig itself only ever walks configPaths() (exe-relative /
	// %APPDATA%), which a t.TempDir() path is never one of, so read the saved
	// file back directly the same way loadConfig would.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var readBack Config
	if err := json.Unmarshal(b, &readBack); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(readBack, want) {
		t.Fatalf("saveConfig then read back = %+v, want %+v", readBack, want)
	}
}

func TestSaveConfigNoPath(t *testing.T) {
	if err := saveConfig("", Config{}); err == nil {
		t.Fatal("saveConfig(\"\", ...) succeeded, want an error")
	}
}

func TestSaveConfigOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bacchus.config.json")

	if err := saveConfig(path, Config{Geo: "us"}); err != nil {
		t.Fatalf("saveConfig (first write): %v", err)
	}
	if err := saveConfig(path, Config{Geo: "de"}); err != nil {
		t.Fatalf("saveConfig (second write): %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var readBack Config
	if err := json.Unmarshal(b, &readBack); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if readBack.Geo != "de" {
		t.Fatalf("after overwrite, Geo = %q, want %q", readBack.Geo, "de")
	}
}
