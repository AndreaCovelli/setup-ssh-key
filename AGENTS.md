# Repository guidance

These instructions apply to the entire repository.

## Project overview

`setup-ssh-key` is a dependency-free Go CLI that generates an SSH key pair,
installs the public key on a remote host, verifies login, and prints an SSH
config entry. The client must build and behave consistently on Linux, macOS,
and Windows. Remote hosts are currently expected to provide a Unix-like shell
and the conventional `~/.ssh/authorized_keys` layout.

## Development commands

Run these checks for code changes:

```sh
gofmt -w <changed-go-files>
go test ./...
go vet ./...
```

Use `go test -race ./...` for changes involving process execution, signals,
I/O, or shared state. Run `staticcheck ./...` when it is available.

Verify portability when changing OS-sensitive code:

```sh
GOOS=windows GOARCH=amd64 go build -o dist/setup-ssh-key.exe .
GOOS=darwin GOARCH=arm64 go build -o dist/setup-ssh-key-darwin .
```

For release or packaging changes, also run:

```sh
shellcheck scripts/build-release.sh
actionlint .github/workflows/*.yml
bash scripts/build-release.sh v0.0.0-local
```

## Code organization

- `app.go` owns the CLI workflow and orchestration.
- `options.go` and `target.go` own parsing and validation.
- `commands.go` isolates external process execution behind `commandRunner`.
- `keyfiles.go` owns backup and rollback behavior.
- `signals_*.go` contains platform-specific signal handling.
- `ui.go` owns terminal output, prompts, colors, and usage text.
- `scripts/build-release.sh` builds release archives for supported platforms.

Keep platform-specific behavior in build-tagged files when APIs differ by OS.
Prefer small, testable helpers over adding more logic directly to `app.run`.

## Safety and behavior requirements

- Treat private-key handling, backups, permissions, and rollback as
  security-sensitive code.
- Never silently overwrite an existing private or public key.
- Preserve the previous key pair when generation fails or is interrupted.
- Do not pass user-controlled values through a local shell. Use argument slices
  with `exec.Command` through `commandRunner`.
- Keep filenames constrained to safe stems and continue validating SSH targets,
  ports, key types, and key sizes before filesystem or network operations.
- Do not add a dependency on `ssh-copy-id`; it is not part of standard Windows
  OpenSSH. The required client commands are `ssh` and `ssh-keygen`.
- Preserve interactive behavior and meaningful exit codes: help/version succeed,
  malformed invocation is a usage error, operational failures are nonzero, and
  interrupts retain conventional signal exit codes.
- Keep ANSI colors conditional and honor `NO_COLOR`.

## Testing conventions

- Add table-driven tests for parsing and validation boundaries.
- Use a fake `commandRunner` for workflow tests; tests must not contact a real
  SSH server, alter the user's SSH directory, or depend on local OpenSSH state.
- Use `t.TempDir` for key files and `t.Setenv` for environment-controlled
  behavior.
- Cover failure and rollback paths whenever key-file lifecycle behavior changes.
- Keep tests portable; avoid Unix-only assumptions outside build-tagged tests.

## Dependencies and generated files

Prefer the Go standard library. Introduce a third-party dependency only when it
materially improves correctness or portability and document the reason.

`dist/` contains generated binaries and archives and must remain untracked. Do
not commit private keys, credentials, local SSH configuration, or GitHub tokens.

## Workflows and releases

GitHub Actions must use explicit least-privilege permissions and bounded job
timeouts. Release assets must be named explicitly rather than uploaded with a
broad `dist/*` glob. Releases are driven by semantic-version tags beginning
with `v` and must continue producing Linux, macOS, and Windows archives for
both `amd64` and `arm64`, plus SHA-256 checksums.
