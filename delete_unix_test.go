//go:build darwin || linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallRemotePublicKeyCommandUsesConventionalAuthorizedKeys(t *testing.T) {
	remoteHome := t.TempDir()
	command := exec.Command("sh", "-c", installRemotePublicKeyCommand)
	command.Env = append(os.Environ(), "HOME="+remoteHome)
	command.Stdin = strings.NewReader("ssh-ed25519 TEST test@example\n")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("remote installation command failed: %v\n%s", err, stderr.String())
	}

	authorizedKeys := filepath.Join(remoteHome, ".ssh", "authorized_keys")
	got, err := os.ReadFile(authorizedKeys)
	if err != nil {
		t.Fatal(err)
	}
	if want := "ssh-ed25519 TEST test@example\n"; string(got) != want {
		t.Fatalf("authorized_keys = %q, want %q", got, want)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Dir(authorizedKeys): 0o700,
		authorizedKeys:               0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("permissions for %q = %o, want %o", path, got, want)
		}
	}
}

func TestRemoveRemotePublicKeyCommandMatchesKeyNotComment(t *testing.T) {
	remoteHome := t.TempDir()
	sshDir := filepath.Join(remoteHome, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	contents := strings.Join([]string{
		"# retained comment",
		"ssh-ed25519 OTHER keep@example",
		`command="echo hello",restrict ssh-ed25519 TEST changed-comment`,
		"ssh-ed25519 TEST duplicate",
		"ssh-rsa TEST different-type",
		"ssh-rsa OTHER note ssh-ed25519 TEST retained-comment-text",
		`command="echo ssh-ed25519 TEST now",restrict ssh-rsa OTHER retained-option-text`,
		"",
	}, "\n")
	if err := os.WriteFile(authorizedKeys, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("sh", "-c", removeRemotePublicKeyCommand)
	command.Env = append(os.Environ(), "HOME="+remoteHome)
	command.Stdin = strings.NewReader("ssh-ed25519 TEST\n")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("remote deletion command failed: %v\n%s", err, output)
	}

	got, err := os.ReadFile(authorizedKeys)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"# retained comment",
		"ssh-ed25519 OTHER keep@example",
		"ssh-rsa TEST different-type",
		"ssh-rsa OTHER note ssh-ed25519 TEST retained-comment-text",
		`command="echo ssh-ed25519 TEST now",restrict ssh-rsa OTHER retained-option-text`,
		"",
	}, "\n")
	if string(got) != want {
		t.Fatalf("authorized_keys after deletion:\n%s\nwant:\n%s", got, want)
	}
	info, err := os.Stat(authorizedKeys)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("authorized_keys permissions = %o", permissions)
	}
}
