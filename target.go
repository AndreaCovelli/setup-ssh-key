package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

type target struct {
	user        string
	host        string
	destination string
	port        int
}

func parseTarget(value string) (target, error) {
	invalid := func() (target, error) {
		return target{}, fmt.Errorf("invalid target %q; expected user@host[:port] or user@[IPv6-address][:port]", value)
	}
	if value == "" || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return invalid()
	}

	user, address, found := strings.Cut(value, "@")
	if !found || user == "" || strings.HasPrefix(user, "-") || address == "" || strings.Contains(address, "@") {
		return invalid()
	}

	host := ""
	portText := ""
	displayHost := ""
	if strings.HasPrefix(address, "[") {
		end := strings.IndexByte(address, ']')
		if end < 2 {
			return invalid()
		}
		host = address[1:end]
		if ip := net.ParseIP(host); ip == nil || ip.To4() != nil {
			return invalid()
		}
		displayHost = "[" + host + "]"
		suffix := address[end+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") || len(suffix) == 1 {
				return invalid()
			}
			portText = suffix[1:]
		}
	} else {
		if strings.Count(address, ":") > 1 {
			return invalid()
		}
		host = address
		if before, after, found := strings.Cut(address, ":"); found {
			if after == "" {
				return invalid()
			}
			host, portText = before, after
		}
		if host == "" || strings.ContainsAny(host, "[]") {
			return invalid()
		}
		displayHost = host
	}

	port := 22
	if portText != "" {
		if len(portText) > 5 || strings.IndexFunc(portText, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return target{}, fmt.Errorf("SSH port must be between 1 and 65535 (got %q)", portText)
		}
		parsed, err := strconv.Atoi(portText)
		if err != nil || parsed < 1 || parsed > 65535 {
			return target{}, fmt.Errorf("SSH port must be between 1 and 65535 (got %q)", portText)
		}
		port = parsed
	}

	return target{
		user:        user,
		host:        host,
		destination: user + "@" + displayHost,
		port:        port,
	}, nil
}
