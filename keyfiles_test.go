package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKeyBackupsRestoreExistingPair(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte("old private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+".pub", []byte("old public"), 0o644); err != nil {
		t.Fatal(err)
	}

	backups := newKeyBackups(keyPath)
	if err := backups.moveAside(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC), 42); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("partial private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backups.restore(true); err != nil {
		t.Fatal(err)
	}

	private, err := os.ReadFile(keyPath)
	if err != nil || string(private) != "old private" {
		t.Fatalf("restored private key = %q, %v", private, err)
	}
	public, err := os.ReadFile(keyPath + ".pub")
	if err != nil || string(public) != "old public" {
		t.Fatalf("restored public key = %q, %v", public, err)
	}
}

func TestKeyBackupsRejectDirectory(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	backups := newKeyBackups(keyPath)
	if err := backups.rejectDirectories(); err == nil {
		t.Fatal("rejectDirectories() unexpectedly succeeded")
	}
}
