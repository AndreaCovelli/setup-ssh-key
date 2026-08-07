package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	keyPath      string
	uploadedKey  string
	verification []string
}

type namedSignal string

func (signal namedSignal) String() string { return string(signal) }
func (namedSignal) Signal()               {}

type interruptRunner struct {
	started  chan struct{}
	release  chan struct{}
	canceled chan struct{}
}

func (runner *interruptRunner) lookPath(name string) (string, error) {
	return name, nil
}

func (runner *interruptRunner) run(ctx context.Context, name string, _ []string, _ io.Reader, _, _ io.Writer) error {
	if name != "ssh-keygen" {
		return fmt.Errorf("unexpected command %q", name)
	}
	close(runner.started)
	select {
	case <-ctx.Done():
		close(runner.canceled)
		return ctx.Err()
	case <-runner.release:
		return errors.New("released without cancellation")
	}
}

func (runner *interruptRunner) combinedOutput(name string, _ []string) ([]byte, error) {
	return nil, fmt.Errorf("unexpected command %q", name)
}

func (runner *fakeRunner) lookPath(name string) (string, error) {
	if name == "ssh-add" {
		return "", errors.New("not found")
	}
	return name, nil
}

func (runner *fakeRunner) run(_ context.Context, name string, args []string, stdin io.Reader, _, _ io.Writer) error {
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

func TestAppHelpAndVersionDoNotRequireHomeDirectory(t *testing.T) {
	for _, name := range []string{"HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "KEY_DIR"} {
		t.Setenv(name, "")
	}

	for _, args := range [][]string{{"-h"}, {"--version"}} {
		var stdout, stderr bytes.Buffer
		application := newApp(strings.NewReader(""), &stdout, &stderr)
		if exitCode := application.run(args); exitCode != 0 {
			t.Errorf("run(%v) exit code = %d, stderr = %s", args, exitCode, stderr.String())
		}
	}
}

func TestAppReturnsUsageErrorForMalformedInvocation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KEY_DIR", "")

	tests := []struct {
		name        string
		args        []string
		wantMessage string
	}{
		{"unknown flag", []string{"--definitely-invalid"}, "flag provided but not defined"},
		{"invalid target", []string{"malformed-target"}, "invalid target"},
		{"invalid key type", []string{"-t", "dsa", "alice@host"}, "unsupported key type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			application := newApp(strings.NewReader(""), &stdout, &stderr)
			if exitCode := application.run(test.args); exitCode != 2 {
				t.Fatalf("run(%v) exit code = %d, stderr = %s", test.args, exitCode, stderr.String())
			}
			if count := strings.Count(stderr.String(), test.wantMessage); count != 1 {
				t.Errorf("stderr contains %q %d times:\n%s", test.wantMessage, count, stderr.String())
			}
			if count := strings.Count(stderr.String(), "Usage:"); count != 1 {
				t.Errorf("stderr contains usage %d times:\n%s", count, stderr.String())
			}
		})
	}
}

func TestInstallPublicKeyRejectsMultipleLines(t *testing.T) {
	publicPath := filepath.Join(t.TempDir(), "key.pub")
	contents := "ssh-ed25519 TEST expected@example\nssh-ed25519 EXTRA unexpected@example\n"
	if err := os.WriteFile(publicPath, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	application := newApp(strings.NewReader(""), io.Discard, io.Discard)
	runner := &fakeRunner{}
	application.runner = runner
	remote, err := parseTarget("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if err := application.installPublicKey(publicPath, remote); err == nil {
		t.Fatal("installPublicKey() unexpectedly accepted multiple lines")
	}
	if runner.uploadedKey != "" {
		t.Fatalf("uploaded key = %q", runner.uploadedKey)
	}
}

func TestInstallPublicKeyAcceptsSingleCRLFLine(t *testing.T) {
	publicPath := filepath.Join(t.TempDir(), "key.pub")
	contents := "ssh-ed25519 TEST expected@example\r\n"
	if err := os.WriteFile(publicPath, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	application := newApp(strings.NewReader(""), io.Discard, io.Discard)
	runner := &fakeRunner{}
	application.runner = runner
	remote, err := parseTarget("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if err := application.installPublicKey(publicPath, remote); err != nil {
		t.Fatalf("installPublicKey() error = %v", err)
	}
	if runner.uploadedKey != "ssh-ed25519 TEST expected@example\n" {
		t.Fatalf("uploaded key = %q", runner.uploadedKey)
	}
}

func TestQuoteArgumentProtectsShellMetacharacters(t *testing.T) {
	for _, value := range []string{"semi;colon", "$HOME", "`whoami`", "single'quote"} {
		quoted := quoteArgument(value)
		if quoted == value || !strings.HasPrefix(quoted, "'") || !strings.HasSuffix(quoted, "'") {
			t.Errorf("quoteArgument(%q) = %q", value, quoted)
		}
	}
}

func TestAppInterruptCancelsGenerationAndRestoresKeys(t *testing.T) {
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "test_key")
	if err := os.WriteFile(keyPath, []byte("old private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+".pub", []byte("old public"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEY_DIR", keyDir)
	t.Setenv("COMMENT", "test@example")
	t.Setenv("NO_COLOR", "1")

	runner := &interruptRunner{
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	application := newApp(strings.NewReader("y\n"), io.Discard, io.Discard)
	application.runner = runner
	application.notifySignals = func(channel chan<- os.Signal, _ ...os.Signal) {
		channel <- namedSignal("terminate")
	}
	application.stopSignals = func(chan<- os.Signal) {}

	exitCodes := make(chan int, 1)
	go func() {
		exitCodes <- application.run([]string{"-k", "test_key", "alice@example.com"})
	}()
	<-runner.started

	var exitCode int
	select {
	case exitCode = <-exitCodes:
	case <-time.After(time.Second):
		close(runner.release)
		exitCode = <-exitCodes
		t.Fatalf("run() did not cancel key generation after the signal; exit code after release = %d", exitCode)
	}
	close(runner.release)

	if exitCode != 143 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	select {
	case <-runner.canceled:
	default:
		t.Fatal("command context was not canceled")
	}
	for path, want := range map[string]string{
		keyPath:          "old private",
		keyPath + ".pub": "old public",
	} {
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != want {
			t.Errorf("restored %s = %q, %v", path, contents, err)
		}
	}
}
