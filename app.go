package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var errUsage = errors.New("usage")

type app struct {
	in            *bufio.Reader
	commandIn     io.Reader
	out           io.Writer
	errOut        io.Writer
	colors        palette
	runner        commandRunner
	notifySignals func(chan<- os.Signal, ...os.Signal)
	stopSignals   func(chan<- os.Signal)
}

func newApp(in io.Reader, out, errOut io.Writer) *app {
	return &app{
		in:            bufio.NewReader(in),
		commandIn:     in,
		out:           out,
		errOut:        errOut,
		colors:        colorsFor(out),
		runner:        systemRunner{},
		notifySignals: signal.Notify,
		stopSignals:   signal.Stop,
	}
}

func (a *app) run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "completion":
			return a.runCompletion(args[1:])
		case "__complete-keys":
			return a.runCompletionKeys(args[1:])
		}
	}

	opts, err := parseOptions(args, "", a.errOut)
	if errors.Is(err, flagHelpError()) {
		return 0
	}
	if errors.Is(err, errUsage) {
		if err != errUsage {
			a.fail("%v", err)
		}
		printUsage(a.errOut)
		return 2
	}
	if err != nil {
		return a.fail("%v", err)
	}
	if opts.showVersion {
		fmt.Fprintf(a.out, "%s %s\n", programName(), version)
		return 0
	}
	if opts.keyDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return a.fail("could not determine the home directory: %v", err)
		}
		opts.keyDir = filepath.Join(home, ".ssh")
		if err := validateKeyDir(opts.keyDir); err != nil {
			return a.fail("%v", err)
		}
	}

	localHost, err := os.Hostname()
	if err != nil || localHost == "" {
		return a.fail("could not determine the local hostname")
	}
	if before, _, found := strings.Cut(localHost, "."); found {
		localHost = before
	}
	if localHost == "" {
		return a.fail("could not determine the local hostname")
	}
	if opts.keyName == "" {
		opts.keyName = defaultKeyName(opts.target.host, localHost)
	}
	if err := validateKeyName(opts.keyName); err != nil {
		return a.fail("%v", err)
	}
	keyPath := filepath.Join(opts.keyDir, opts.keyName)
	if opts.deleteKey {
		return a.runDelete(keyPath, opts.target)
	}

	if opts.comment == "" {
		localUser, err := currentUsername()
		if err != nil {
			return a.fail("could not determine the local user: %v", err)
		}
		opts.comment = localUser + "@" + localHost
	}
	if err := validateComment(opts.comment); err != nil {
		return a.fail("%v", err)
	}

	if opts.keyBits < 0 {
		a.warn("ed25519 does not use -b; ignoring it.")
		opts.keyBits = 0
	}
	if opts.emptyPassword {
		a.warn("You requested a key with no passphrase.")
		a.warn("Anyone who obtains the private key file will have immediate access.")
		fmt.Fprintln(a.out)
		if !a.confirm("Confirm empty passphrase? [y/N]:", false) {
			return a.fail("aborted; re-run without -i to set a passphrase")
		}
	}

	for _, command := range []string{"ssh-keygen", "ssh"} {
		if _, err := a.runner.lookPath(command); err != nil {
			return a.fail("%q not found; install OpenSSH and ensure it is on PATH", command)
		}
	}
	if err := os.MkdirAll(opts.keyDir, 0o700); err != nil {
		return a.fail("create key directory %q: %v", opts.keyDir, err)
	}
	if err := os.Chmod(opts.keyDir, 0o700); err != nil {
		return a.fail("secure key directory %q: %v", opts.keyDir, err)
	}

	a.header("══ SSH Key Setup ══════════════════════════════════════")
	a.info("Key type   : %s%s", opts.keyType, bitSuffix(opts.keyBits))
	a.info("Key path   : %s", keyPath)
	a.info("Remote     : %s:%d", opts.target.destination, opts.target.port)
	a.info("Comment    : %s", opts.comment)
	fmt.Fprintln(a.out)

	backups := newKeyBackups(keyPath)
	if err := backups.rejectDirectories(); err != nil {
		return a.fail("%v", err)
	}
	exists, err := backups.anyKeyExists()
	if err != nil {
		return a.fail("%v", err)
	}
	if exists {
		a.warn("A private or public key already exists at %q.", keyPath)
		if !a.confirm("Back it up and replace it? [y/N]:", false) {
			a.info("Aborted.")
			return 0
		}
		if err := backups.moveAside(time.Now(), os.Getpid()); err != nil {
			return a.fail("could not back up the existing key files: %v", err)
		}
		a.info("Existing key files were moved to unique timestamped backups.")
	}

	keygenArgs := []string{"-t", opts.keyType, "-C", opts.comment, "-f", keyPath}
	if opts.keyBits > 0 {
		keygenArgs = append(keygenArgs, "-b", strconv.Itoa(opts.keyBits))
	}
	if opts.emptyPassword {
		keygenArgs = append(keygenArgs, "-N", "")
	}

	a.info("Generating SSH key pair…")
	signalChannel := make(chan os.Signal, 1)
	a.notifySignals(signalChannel, generationSignals()...)
	generationContext, cancelGeneration := context.WithCancel(context.Background())
	commandResult := make(chan error, 1)
	go func() {
		commandResult <- a.runner.run(generationContext, "ssh-keygen", keygenArgs, a.commandIn, a.out, a.errOut)
	}()

	var generationErr error
	var interrupted os.Signal
	select {
	case generationErr = <-commandResult:
		a.stopSignals(signalChannel)
		select {
		case interrupted = <-signalChannel:
		default:
		}
	case interrupted = <-signalChannel:
		a.stopSignals(signalChannel)
		cancelGeneration()
		generationErr = <-commandResult
	}
	cancelGeneration()
	if generationErr != nil || interrupted != nil {
		if restoreErr := backups.restore(true); restoreErr != nil {
			return a.fail("ssh-keygen failed and the previous key pair could not be fully restored: %v", restoreErr)
		}
		if interrupted != nil {
			a.warn("Interrupted; rolled back key generation and restored any previous key pair.")
			if interrupted == os.Interrupt {
				return 130
			}
			return 143
		}
		return a.fail("ssh-keygen failed; restored any previous key pair")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return a.fail("set private-key permissions: %v", err)
	}
	if err := os.Chmod(keyPath+".pub", 0o644); err != nil {
		return a.fail("set public-key permissions: %v", err)
	}

	a.success("Key pair created:")
	fmt.Fprintf(a.out, "  Private : %s\n  Public  : %s\n\n", keyPath, keyPath+".pub")

	if err := a.installPublicKey(keyPath+".pub", opts.target); err != nil {
		return a.fail("public-key installation failed; the local key remains at %q: %v", keyPath, err)
	}
	a.success("Public key installed on the remote host.")

	fmt.Fprintln(a.out)
	a.info("Verifying key-based login…")
	verifyArgs := sshArgs(opts.target, "-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "PubkeyAuthentication=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "BatchMode=no",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=yes",
		opts.target.destination, "true")
	verifyErr := a.runner.run(context.Background(), "ssh", verifyArgs, a.commandIn, a.out, a.errOut)
	if verifyErr == nil {
		a.success("Key-based login works.")
	} else {
		a.warn("Could not verify that the newly generated key was accepted.")
		fmt.Fprintf(a.out, "  Try manually: ssh -i %s -p %d %s\n", quoteArgument(keyPath), opts.target.port, quoteArgument(opts.target.destination))
	}

	fmt.Fprintln(a.out)
	if opts.emptyPassword {
		a.info("No passphrase set; skipping ssh-agent (nothing to cache).")
	} else if _, err := a.runner.lookPath("ssh-add"); err == nil && sshAgentAvailable(a.runner) {
		if a.confirm("Add key to ssh-agent? [Y/n]:", true) {
			if err := a.runner.run(context.Background(), "ssh-add", []string{keyPath}, a.commandIn, a.out, a.errOut); err != nil {
				a.warn("Failed to add the key to ssh-agent. You can try manually later.")
			} else {
				a.success("Key added to ssh-agent.")
			}
		}
	} else {
		a.info("ssh-agent not running; to add the key later: ssh-add %s", quoteArgument(keyPath))
	}

	fmt.Fprintln(a.out)
	a.header("── Optional ~/.ssh/config entry ───────────────────────")
	fmt.Fprintf(a.out, "Host %s\n    HostName     %s\n    User         %s\n", opts.target.host, opts.target.host, opts.target.user)
	if opts.target.port != 22 {
		fmt.Fprintf(a.out, "    Port         %d\n", opts.target.port)
	}
	fmt.Fprintf(a.out, "    IdentityFile \"%s\"\n", escapeConfigPath(keyPath))
	fmt.Fprintf(a.out, "\n%s%sAll done!%s\n\n", a.colors.green, a.colors.bold, a.colors.reset)
	return 0
}

func (a *app) installPublicKey(publicPath string, remote target) error {
	key, err := readPublicKey(publicPath)
	if err != nil {
		return err
	}

	a.info("Uploading public key to %s:%d…", remote.destination, remote.port)
	a.info("You may be prompted for %s's remote password.", remote.user)
	fmt.Fprintln(a.out)
	remoteCommand := `umask 077; mkdir -p "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys" && chmod 700 "$HOME/.ssh" && chmod 600 "$HOME/.ssh/authorized_keys" && cat >> "$HOME/.ssh/authorized_keys"`
	args := sshArgs(remote, remote.destination, remoteCommand)
	return a.runner.run(context.Background(), "ssh", args, bytes.NewReader(key), a.out, a.errOut)
}

func readPublicKey(path string) ([]byte, error) {
	const maximumPublicKeySize = 64 * 1024

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open public key: %w", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maximumPublicKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	if len(contents) == 0 {
		return nil, errors.New("public key is empty")
	}
	if len(contents) > maximumPublicKeySize {
		return nil, errors.New("public key is unexpectedly large")
	}

	line := contents
	if bytes.HasSuffix(line, []byte("\r\n")) {
		line = line[:len(line)-2]
	} else if bytes.HasSuffix(line, []byte("\n")) {
		line = line[:len(line)-1]
	}
	if len(line) == 0 || bytes.ContainsAny(line, "\r\n") {
		return nil, errors.New("public key must contain exactly one line")
	}
	normalized := append([]byte(nil), line...)
	return append(normalized, '\n'), nil
}

func sshArgs(remote target, rest ...string) []string {
	args := []string{"-p", strconv.Itoa(remote.port)}
	return append(args, rest...)
}

func currentUsername() (string, error) {
	if current, err := user.Current(); err == nil && current.Username != "" {
		name := current.Username
		if slash := strings.LastIndexAny(name, `\\/`); slash >= 0 {
			name = name[slash+1:]
		}
		return name, nil
	}
	for _, variable := range []string{"USER", "USERNAME"} {
		if value := os.Getenv(variable); value != "" {
			return value, nil
		}
	}
	return "", errors.New("username is unavailable")
}

func bitSuffix(bits int) string {
	if bits > 0 {
		return fmt.Sprintf(" (%d-bit)", bits)
	}
	return ""
}

func quoteArgument(value string) string {
	if runtime.GOOS == "windows" {
		return "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func escapeConfigPath(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}
