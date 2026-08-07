package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

type fakeRunner struct {
	keyPath      string
	uploadedKey  string
	verification []string
}

func (runner *fakeRunner) lookPath(name string) (string, error) {
	if name == "ssh-add" {
		return "", errors.New("not found")
	}
	return name, nil
}

func (runner *fakeRunner) run(name string, args []string, stdin io.Reader, _, _ io.Writer) error {
	switch name {
	case "ssh-keygen":
		pathIndex := slices.Index(args, "-f")
		if pathIndex < 0 || pathIndex+1 == len(args) {
			return errors.New("missing key path")
		}
		runner.keyPath = args[pathIndex+1]
		if err := os.WriteFile(runner.keyPath, []byte("private"), 0o600); err != nil {
			return err
		}
		return os.WriteFile(runner.keyPath+".pub", []byte("ssh-ed25519 TEST test@example\n"), 0o644)
	case "ssh":
		key, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		runner.uploadedKey = string(key)
		return nil
	default:
		return fmt.Errorf("unexpected command %q", name)
	}
}

func (runner *fakeRunner) combinedOutput(name string, args []string) ([]byte, error) {
	if name != "ssh" {
		return nil, fmt.Errorf("unexpected command %q", name)
	}
	runner.verification = append([]string(nil), args...)
	return []byte("debug1: Server accepts key: " + runner.keyPath + " ED25519 SHA256:test\n"), nil
}

func TestAppRunsCompleteWorkflow(t *testing.T) {
	keyDir := t.TempDir()
	t.Setenv("KEY_DIR", keyDir)
	t.Setenv("KEY_TYPE", "")
	t.Setenv("KEY_BITS", "")
	t.Setenv("COMMENT", "test@example")
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("NO_COLOR", "1")

	var stdout, stderr bytes.Buffer
	application := newApp(strings.NewReader("y\n"), &stdout, &stderr)
	runner := &fakeRunner{}
	application.runner = runner

	if exitCode := application.run([]string{"-i", "-k", "test_key", "alice@example.com:2222"}); exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if runner.uploadedKey != "ssh-ed25519 TEST test@example\n" {
		t.Fatalf("uploaded key = %q", runner.uploadedKey)
	}
	if !slices.Contains(runner.verification, "IdentitiesOnly=yes") {
		t.Fatalf("verification arguments = %v", runner.verification)
	}
	for _, expected := range []string{
		"Public key installed on the remote host.",
		"Key-based login works.",
		"Port         2222",
		"All done!",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("output does not contain %q:\n%s", expected, stdout.String())
		}
	}
}
