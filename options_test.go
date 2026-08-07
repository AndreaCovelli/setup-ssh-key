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
