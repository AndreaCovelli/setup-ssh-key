package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type palette struct {
	red, green, yellow, cyan, bold, reset string
}

func colorsFor(out io.Writer) palette {
	file, ok := out.(*os.File)
	term := os.Getenv("TERM")
	if !ok || os.Getenv("NO_COLOR") != "" || term == "" || term == "dumb" {
		return palette{}
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return palette{}
	}
	return palette{
		red: "\x1b[0;31m", green: "\x1b[0;32m", yellow: "\x1b[1;33m",
		cyan: "\x1b[0;36m", bold: "\x1b[1m", reset: "\x1b[0m",
	}
}

func programName() string {
	name := filepath.Base(os.Args[0])
	return strings.TrimSuffix(name, filepath.Ext(name))
}

func flagHelpError() error { return flag.ErrHelp }

func printUsage(out io.Writer) {
	fmt.Fprintf(out, `Usage:
  %s [OPTIONS] user@host[:port]
  %s [OPTIONS] user@[IPv6-address][:port]
  %s --delete [-k <name>] user@host[:port]
  %s completion <bash|zsh|fish|powershell>

Options:
  -k <name>   Key filename stem (default: <host>_from_<client>)
  -t <type>   Key type: ed25519 | rsa | ecdsa  (default: ed25519)
  -b <bits>   Key bits for rsa/ecdsa            (default: 4096 / 521)
  -c <text>   Key comment                        (default: user@client)
  -i          Use an empty passphrase after confirmation (not recommended)
  -d, --delete
              Delete the key locally and from the remote host after confirmation
  -h          Show this help
  --version   Show version

Examples:
  %s alice@192.168.1.10
  %s -t rsa -b 4096 alice@myserver.com:2222
  %s -k deploy_key -i deploy@ci-host
  %s 'alice@[2001:db8::10]:2222'
  %s --delete -k deploy_key deploy@ci-host
  %s completion bash
`, programName(), programName(), programName(), programName(), programName(), programName(), programName(), programName(), programName(), programName())
}

func (a *app) confirm(prompt string, defaultYes bool) bool {
	fmt.Fprintf(a.out, "%s%s%s ", a.colors.yellow, prompt, a.colors.reset)
	reply, err := a.in.ReadString('\n')
	if err != nil {
		return false
	}
	reply = strings.TrimSpace(reply)
	switch strings.ToLower(reply) {
	case "y", "yes":
		return true
	case "":
		return defaultYes
	default:
		return false
	}
}

func (a *app) info(format string, values ...any) {
	fmt.Fprintf(a.out, "%s[INFO]%s  %s\n", a.colors.cyan, a.colors.reset, fmt.Sprintf(format, values...))
}

func (a *app) success(format string, values ...any) {
	fmt.Fprintf(a.out, "%s[OK]%s    %s\n", a.colors.green, a.colors.reset, fmt.Sprintf(format, values...))
}

func (a *app) warn(format string, values ...any) {
	fmt.Fprintf(a.out, "%s[WARN]%s  %s\n", a.colors.yellow, a.colors.reset, fmt.Sprintf(format, values...))
}

func (a *app) fail(format string, values ...any) int {
	fmt.Fprintf(a.errOut, "%s[ERROR]%s %s\n", a.colors.red, a.colors.reset, fmt.Sprintf(format, values...))
	return 1
}

func (a *app) header(value string) {
	fmt.Fprintf(a.out, "\n%s%s%s\n", a.colors.bold, value, a.colors.reset)
}
