//go:build darwin || linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
