package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppGeneratesDeletionCompletionForCommonShells(t *testing.T) {
	tests := []struct {
		shell        string
		registration string
	}{
		{shell: "bash", registration: "complete -F"},
		{shell: "zsh", registration: "compdef"},
		{shell: "fish", registration: "complete -c"},
		{shell: "powershell", registration: "Register-ArgumentCompleter -CommandName"},
	}
	for _, test := range tests {
		t.Run(test.shell, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			application := newApp(strings.NewReader(""), &stdout, &stderr)

			if exitCode := application.run([]string{"completion", test.shell}); exitCode != 0 {
				t.Fatalf("run() exit code = %d, stderr = %s", exitCode, stderr.String())
			}
			for _, expected := range []string{test.registration, "__complete-keys", "--delete", "-d", "-k"} {
				if !strings.Contains(stdout.String(), expected) {
					t.Errorf("%s completion does not contain %q:\n%s", test.shell, expected, stdout.String())
				}
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %s", stderr.String())
			}
		})
	}
}

func TestAppCompletionListsSafePublicKeyStems(t *testing.T) {
	keyDir := t.TempDir()
	for _, name := range []string{
		"alpha.pub",
		"z-last.pub",
		"private_only",
		"private_only.pub.bak.20260807",
		"two words.pub",
		".pub",
		"..pub",
	} {
		if err := os.WriteFile(filepath.Join(keyDir, name), []byte("ssh-ed25519 TEST test@example\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(keyDir, "corrupt.pub"), []byte("not a public key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(keyDir, "directory.pub"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEY_DIR", keyDir)

	var stdout, stderr bytes.Buffer
	application := newApp(strings.NewReader(""), &stdout, &stderr)
	if exitCode := application.run([]string{"__complete-keys"}); exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if got, want := stdout.String(), "alpha\nz-last\n"; got != want {
		t.Fatalf("completion candidates = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestAppCompletionQuietlyHandlesMissingKeyDirectory(t *testing.T) {
	t.Setenv("KEY_DIR", filepath.Join(t.TempDir(), "missing"))

	var stdout, stderr bytes.Buffer
	application := newApp(strings.NewReader(""), &stdout, &stderr)
	if exitCode := application.run([]string{"__complete-keys"}); exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("completion output = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestAppRejectsUnsupportedCompletionShell(t *testing.T) {
	var stdout, stderr bytes.Buffer
	application := newApp(strings.NewReader(""), &stdout, &stderr)

	if exitCode := application.run([]string{"completion", "nushell"}); exitCode != 2 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "unsupported completion shell") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}
