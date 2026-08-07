package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var validKeyName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type invocationError struct {
	err error
}

func (err invocationError) Error() string {
	return err.err.Error()
}

func (invocationError) Is(target error) bool {
	return target == errUsage
}

func usageError(err error) error {
	return invocationError{err: err}
}

type options struct {
	keyName       string
	keyType       string
	keyBits       int
	keyDir        string
	comment       string
	emptyPassword bool
	showVersion   bool
	target        target
}

func parseOptions(args []string, home string, stderr io.Writer) (options, error) {
	keyDir := os.Getenv("KEY_DIR")
	if keyDir == "" && home != "" {
		keyDir = filepath.Join(home, ".ssh")
	}
	opts := options{
		keyType: envOr("KEY_TYPE", "ed25519"),
		keyDir:  keyDir,
		comment: os.Getenv("COMMENT"),
	}
	bits := os.Getenv("KEY_BITS")

	flags := flag.NewFlagSet(programName(), flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.keyName, "k", "", "key filename stem")
	flags.StringVar(&opts.keyType, "t", opts.keyType, "key type")
	flags.StringVar(&bits, "b", bits, "key size in bits")
	flags.StringVar(&opts.comment, "c", opts.comment, "key comment")
	flags.BoolVar(&opts.emptyPassword, "i", false, "use an empty passphrase after confirmation")
	flags.BoolVar(&opts.showVersion, "version", false, "show version")
	flags.Usage = func() {}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stderr)
			return options{}, err
		}
		return options{}, usageError(err)
	}
	if opts.showVersion {
		return opts, nil
	}
	if flags.NArg() != 1 {
		return options{}, errUsage
	}

	parsedTarget, err := parseTarget(flags.Arg(0))
	if err != nil {
		return options{}, usageError(err)
	}
	opts.target = parsedTarget

	switch opts.keyType {
	case "ed25519":
		if bits != "" {
			// A negative sentinel lets the caller print the compatibility warning.
			opts.keyBits = -1
		}
	case "rsa":
		if bits == "" {
			bits = "4096"
		}
		value, err := decimalInteger(bits)
		if err != nil {
			return options{}, usageError(fmt.Errorf("RSA key size must be an integer (got %q)", bits))
		}
		if value < 2048 || value > 16384 {
			return options{}, usageError(fmt.Errorf("RSA key size must be between 2048 and 16384 bits (got %d)", value))
		}
		opts.keyBits = value
	case "ecdsa":
		if bits == "" {
			bits = "521"
		}
		value, err := decimalInteger(bits)
		if err != nil || (value != 256 && value != 384 && value != 521) {
			return options{}, usageError(fmt.Errorf("ECDSA key size must be 256, 384, or 521 (got %q)", bits))
		}
		opts.keyBits = value
	default:
		return options{}, usageError(fmt.Errorf("unsupported key type %q; use ed25519, rsa, or ecdsa", opts.keyType))
	}

	if opts.keyName != "" {
		if err := validateKeyName(opts.keyName); err != nil {
			return options{}, usageError(err)
		}
	}
	if err := validateComment(opts.comment); err != nil {
		return options{}, usageError(err)
	}
	if opts.keyDir != "" {
		if err := validateKeyDir(opts.keyDir); err != nil {
			return options{}, usageError(err)
		}
	}
	return opts, nil
}

func decimalInteger(value string) (int, error) {
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("not a decimal integer")
	}
	return strconv.Atoi(value)
}

func validateKeyName(name string) error {
	if !validKeyName.MatchString(name) || name == "." || name == ".." {
		return fmt.Errorf("invalid key name %q; use only letters, digits, dots, dashes, and underscores", name)
	}
	return nil
}

func validateComment(comment string) error {
	if strings.ContainsAny(comment, "\x00\r\n") {
		return errors.New("key comment must be a single line")
	}
	return nil
}

func validateKeyDir(path string) error {
	if strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("key directory must be a single line")
	}
	return nil
}

func defaultKeyName(remoteHost, localHost string) string {
	return sanitizeName(remoteHost) + "_from_" + sanitizeName(localHost)
}

func sanitizeName(value string) string {
	var result strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			result.WriteRune(r)
		} else {
			result.WriteByte('_')
		}
	}
	return result.String()
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
