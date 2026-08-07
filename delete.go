package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"
)

var validPublicKeyType = regexp.MustCompile(`^[A-Za-z0-9@._+-]+$`)

const removeRemotePublicKeyCommand = `set -eu
umask 077
auth="$HOME/.ssh/authorized_keys"
IFS=' ' read -r target_type target_blob
[ -n "$target_type" ] && [ -n "$target_blob" ]
[ -f "$auth" ] || exit 0
tmp="${auth}.setup-ssh-key.$$"
if (set -C; : > "$tmp") 2>/dev/null; then :; else exit 1; fi
trap 'rm -f "$tmp"' 0 1 2 3 15
awk -v target_type="$target_type" -v target_blob="$target_blob" '
function next_token(line, start, i, c, quoted, escaped, begin) {
    for (i = start; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (c != " " && c != "\t") break
    }
    begin = i
    quoted = 0
    escaped = 0
    for (; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (escaped) {
            escaped = 0
        } else if (quoted && c == "\\") {
            escaped = 1
        } else if (c == "\"") {
            quoted = !quoted
        } else if (!quoted && (c == " " || c == "\t")) {
            token_end = i
            return substr(line, begin, i - begin)
        }
    }
    token_end = length(line) + 1
    return substr(line, begin)
}
{
    first = next_token($0, 1)
    second = next_token($0, token_end)
    if (first == target_type && second == target_blob) next
    if (second == target_type && next_token($0, token_end) == target_blob) next
    print
}' "$auth" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$auth"`

func (a *app) runDelete(keyPath string, remote target) int {
	if _, err := a.runner.lookPath("ssh"); err != nil {
		return a.fail("%q not found; install OpenSSH and ensure it is on PATH", "ssh")
	}

	backups := newKeyBackups(keyPath)
	if err := backups.rejectDirectories(); err != nil {
		return a.fail("%v", err)
	}
	exists, err := backups.anyKeyExists()
	if err != nil {
		return a.fail("%v", err)
	}
	if !exists {
		return a.fail("no local key files exist at %q or %q", keyPath, keyPath+".pub")
	}

	publicKey, err := readPublicKey(keyPath + ".pub")
	if err != nil {
		return a.fail("cannot identify the remote public key; no files were deleted: %v", err)
	}
	identity, err := publicKeyIdentity(publicKey)
	if err != nil {
		return a.fail("cannot identify the remote public key; no files were deleted: %v", err)
	}

	a.header("══ SSH Key Deletion ═══════════════════════════════════")
	a.info("Key path   : %s", keyPath)
	a.info("Remote     : %s:%d", remote.destination, remote.port)
	a.warn("This will remove the matching remote authorization and both local key files.")
	if !a.confirm("Delete this key locally and remotely? [y/N]:", false) {
		a.info("Aborted.")
		return 0
	}

	identityPath := ""
	privateExists, err := pathExists(keyPath)
	if err != nil {
		return a.fail("could not inspect the local private key; no files were deleted: %v", err)
	}
	if privateExists {
		identityPath = keyPath
	}
	if err := a.removeRemotePublicKey(identity, identityPath, remote); err != nil {
		return a.fail("remote public-key deletion failed; the local key pair remains unchanged: %v", err)
	}
	a.success("Remote public key removed.")

	if err := backups.moveAside(time.Now(), os.Getpid()); err != nil {
		return a.fail("remote public key was removed, but the local key pair could not be staged for deletion: %v", err)
	}
	// Re-read the public key from its staged path so a concurrent file change
	// cannot make us delete a different local key pair.
	publicKey, err = readPublicKey(backups.publicBackup)
	var stagedIdentity []byte
	if err == nil {
		stagedIdentity, err = publicKeyIdentity(publicKey)
	}
	if err == nil && !bytes.Equal(identity, stagedIdentity) {
		err = errors.New("public key changed during deletion")
	}
	if err != nil {
		if restoreErr := backups.restore(false); restoreErr != nil {
			return a.fail("remote public key was removed, the staged local public key changed, and the local key pair could not be fully restored: %v", errors.Join(err, restoreErr))
		}
		return a.fail("remote public key was removed, but the local key pair changed and was restored instead of being deleted: %v", err)
	}

	if err := backups.discard(); err != nil {
		return a.fail("remote public key was removed, but the staged local key files could not be fully deleted: %v", err)
	}
	a.success("Local key pair deleted.")
	return 0
}

func (a *app) removeRemotePublicKey(identity []byte, identityPath string, remote target) error {
	a.info("Removing public key from %s:%d…", remote.destination, remote.port)
	a.info("You may be prompted for %s's remote password or key passphrase.", remote.user)

	args := sshArgs(remote)
	if identityPath != "" {
		args = append(args, "-i", identityPath, "-o", "IdentitiesOnly=yes")
	}
	args = append(args, remote.destination, removeRemotePublicKeyCommand)
	return a.runner.run(context.Background(), "ssh", args, bytes.NewReader(identity), a.out, a.errOut)
}

func publicKeyIdentity(publicKey []byte) ([]byte, error) {
	fields := bytes.Fields(publicKey)
	if len(fields) < 2 {
		return nil, errors.New("public key must contain a key type and encoded key")
	}
	if !validPublicKeyType.Match(fields[0]) {
		return nil, fmt.Errorf("invalid public-key type %q", fields[0])
	}
	decoded, err := base64.StdEncoding.DecodeString(string(fields[1]))
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("public key has invalid base64 data")
	}
	identity := append([]byte(nil), fields[0]...)
	identity = append(identity, ' ')
	identity = append(identity, fields[1]...)
	return append(identity, '\n'), nil
}
