# setup-ssh-key

`setup-ssh-key` generates a dedicated SSH key pair, installs the public key on a
remote host, verifies the new credentials, and prints a ready-to-use SSH config
entry. It is a portable Go replacement for the original Bash script.

The client runs on Linux, macOS, and Windows. It requires `ssh` and `ssh-keygen`
from OpenSSH on `PATH`; unlike the Bash version, it does not require
`ssh-copy-id`. The remote host is expected to provide a Unix-like shell and the
usual `~/.ssh/authorized_keys` layout.

## Install

```sh
go install github.com/AndreaCovelli/setup-ssh-key@latest
```

Or build the current checkout:

```sh
go build .
```

On Windows, run the same commands in PowerShell and ensure the optional OpenSSH
Client Windows feature is installed.

## Use

```text
setup-ssh-key [OPTIONS] user@host[:port]
setup-ssh-key [OPTIONS] user@[IPv6-address][:port]
setup-ssh-key completion <bash|zsh|fish|powershell>
```

Examples:

```sh
setup-ssh-key alice@192.168.1.10
setup-ssh-key -t rsa -b 4096 alice@example.com:2222
setup-ssh-key -k deploy_key -i deploy@ci-host
setup-ssh-key 'alice@[2001:db8::10]:2222'
setup-ssh-key --delete -k deploy_key deploy@ci-host
```

Use `setup-ssh-key -h` for all flags. Defaults can also be set with `KEY_TYPE`,
`KEY_BITS`, `KEY_DIR`, and `COMMENT`. Set `NO_COLOR` to disable ANSI colors.

Existing key files are never silently overwritten. With confirmation, they are
moved to unique timestamped backups; if key generation fails or is interrupted,
the previous pair is restored.

To remove a generated key from both locations, run with `--delete` (or `-d`)
and the same target and key name used during setup. After confirmation, the
matching cryptographic key is removed from the remote `authorized_keys` file,
then the local private and public files are deleted. If the remote operation
fails, the local pair remains unchanged. The local `.pub` file is required so
the remote entry can be identified safely.

The remote host's `known_hosts` entry is deliberately left unchanged. It
records the server's identity rather than the user's authorization key, so
removing it would weaken host-key verification for future connections.

### Shell completion

Enable dynamic key-name completion for the current shell session:

```sh
# Bash
source <(setup-ssh-key completion bash)

# Zsh
source <(setup-ssh-key completion zsh)

# Fish
setup-ssh-key completion fish | source
```

For PowerShell:

```powershell
setup-ssh-key completion powershell | Out-String | Invoke-Expression
```

After activation, pressing Tab after `setup-ssh-key --delete -k` suggests valid
local public-key stems from `KEY_DIR` or `~/.ssh`. Add the activation command to
the appropriate shell profile to persist it across sessions.

## Develop

Install the pinned development tools and run every repository check:

```sh
mise install
mise run check
```

The individual Go commands remain available when working without mise:

```sh
go test ./...
go vet ./...
```

To verify the Windows build from another platform:

```sh
GOOS=windows GOARCH=amd64 go build -o dist/setup-ssh-key.exe .
```

## Releases

Push a semantic-version tag to build and publish a GitHub release:

```sh
git tag v1.0.0
git push origin v1.0.0
```

The release workflow tests the repository, builds `amd64` and `arm64` archives
for Linux, macOS, and Windows, verifies their contents, and publishes SHA-256
checksums with generated release notes.
