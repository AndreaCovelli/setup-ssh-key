package main

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name, input, user, host, destination string
		port                                 int
	}{
		{"hostname", "alice@example.com", "alice", "example.com", "alice@example.com", 22},
		{"IPv4 and port", "root@192.0.2.4:2222", "root", "192.0.2.4", "root@192.0.2.4", 2222},
		{"IPv6", "alice@[2001:db8::10]", "alice", "2001:db8::10", "alice@[2001:db8::10]", 22},
		{"IPv6 and port", "alice@[2001:db8::10]:2200", "alice", "2001:db8::10", "alice@[2001:db8::10]", 2200},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseTarget(test.input)
			if err != nil {
				t.Fatalf("parseTarget() error = %v", err)
			}
			if got.user != test.user || got.host != test.host || got.destination != test.destination || got.port != test.port {
				t.Fatalf("parseTarget() = %#v", got)
			}
		})
	}
}

func TestParseTargetRejectsInvalidInput(t *testing.T) {
	inputs := []string{
		"", "host", "@host", "alice@", "alice @host", "alice@host:", "alice@host:0",
		"alice@host:65536", "alice@host:not-a-port", "alice@2001:db8::1",
		"alice@[192.0.2.1]", "alice@[not-ipv6]", "alice@[2001:db8::1]oops",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			if _, err := parseTarget(input); err == nil {
				t.Fatalf("parseTarget(%q) unexpectedly succeeded", input)
			}
		})
	}
}
