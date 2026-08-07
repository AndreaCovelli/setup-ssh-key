package main

import (
	"io"
	"testing"
)

func TestParseOptionsKeyTypes(t *testing.T) {
	t.Setenv("KEY_TYPE", "")
	t.Setenv("KEY_BITS", "")
	t.Setenv("KEY_DIR", "")
	t.Setenv("COMMENT", "")

	tests := []struct {
		args      []string
		keyType   string
		keyBits   int
		wantError bool
	}{
		{[]string{"alice@host"}, "ed25519", 0, false},
		{[]string{"-t", "rsa", "alice@host"}, "rsa", 4096, false},
		{[]string{"-t", "rsa", "-b", "2048", "alice@host"}, "rsa", 2048, false},
		{[]string{"-t", "ecdsa", "alice@host"}, "ecdsa", 521, false},
		{[]string{"-t", "ecdsa", "-b", "384", "alice@host"}, "ecdsa", 384, false},
		{[]string{"-t", "rsa", "-b", "1024", "alice@host"}, "", 0, true},
		{[]string{"-t", "ecdsa", "-b", "512", "alice@host"}, "", 0, true},
		{[]string{"-t", "dsa", "alice@host"}, "", 0, true},
	}
	for _, test := range tests {
		opts, err := parseOptions(test.args, "/home/test", io.Discard)
		if (err != nil) != test.wantError {
			t.Fatalf("parseOptions(%v) error = %v", test.args, err)
		}
		if err == nil && (opts.keyType != test.keyType || opts.keyBits != test.keyBits) {
			t.Fatalf("parseOptions(%v) = type %q, bits %d", test.args, opts.keyType, opts.keyBits)
		}
	}
}

func TestKeyNames(t *testing.T) {
	if got := defaultKeyName("2001:db8::1", "work station"); got != "2001_db8__1_from_work_station" {
		t.Fatalf("defaultKeyName() = %q", got)
	}
	for _, invalid := range []string{"", ".", "..", "a/b", `a\\b`, "two words"} {
		if err := validateKeyName(invalid); err == nil {
			t.Errorf("validateKeyName(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestParseOptionsVersionNeedsNoTarget(t *testing.T) {
	opts, err := parseOptions([]string{"--version"}, t.TempDir(), io.Discard)
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if !opts.showVersion {
		t.Fatal("parseOptions() did not set showVersion")
	}
}

func TestParseOptionsRejectsMultilineValues(t *testing.T) {
	t.Run("comment", func(t *testing.T) {
		t.Setenv("KEY_DIR", "")
		if _, err := parseOptions([]string{"-c", "expected\nssh-ed25519 EXTRA unexpected", "alice@host"}, t.TempDir(), io.Discard); err == nil {
			t.Fatal("parseOptions() unexpectedly accepted a multiline comment")
		}
	})

	t.Run("key directory", func(t *testing.T) {
		t.Setenv("KEY_DIR", "keys\nHost *")
		if _, err := parseOptions([]string{"alice@host"}, t.TempDir(), io.Discard); err == nil {
			t.Fatal("parseOptions() unexpectedly accepted a multiline key directory")
		}
	})
}

func TestParseOptionsDeleteMode(t *testing.T) {
	t.Setenv("KEY_TYPE", "unsupported-for-generation")
	t.Setenv("KEY_BITS", "not-a-number")
	t.Setenv("COMMENT", "ignored\nfor deletion")
	t.Setenv("KEY_DIR", "")

	for _, flag := range []string{"-d", "--delete"} {
		opts, err := parseOptions([]string{flag, "-k", "test_key", "alice@host"}, t.TempDir(), io.Discard)
		if err != nil {
			t.Fatalf("parseOptions(%q) error = %v", flag, err)
		}
		if !opts.deleteKey || opts.keyName != "test_key" {
			t.Fatalf("parseOptions(%q) = %#v", flag, opts)
		}
	}
}

func TestParseOptionsRejectsGenerationFlagsInDeleteMode(t *testing.T) {
	t.Setenv("KEY_TYPE", "")
	t.Setenv("KEY_BITS", "")
	t.Setenv("COMMENT", "")
	t.Setenv("KEY_DIR", "")

	tests := [][]string{
		{"--delete", "-t", "rsa", "alice@host"},
		{"--delete", "-b", "4096", "alice@host"},
		{"--delete", "-c", "comment", "alice@host"},
		{"--delete", "-i", "alice@host"},
	}
	for _, args := range tests {
		if _, err := parseOptions(args, t.TempDir(), io.Discard); err == nil {
			t.Errorf("parseOptions(%v) unexpectedly succeeded", args)
		}
	}
}
