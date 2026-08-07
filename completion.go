package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const bashCompletion = `# Bash completion for setup-ssh-key deletion key names.
_setup_ssh_key_delete_completion() {
    local current previous word deleting key
    COMPREPLY=()
    current=${COMP_WORDS[COMP_CWORD]}
    previous=
    if (( COMP_CWORD > 0 )); then
        previous=${COMP_WORDS[COMP_CWORD-1]}
    fi
    deleting=
    for word in "${COMP_WORDS[@]}"; do
        case "$word" in
            -d|--delete) deleting=1 ;;
        esac
    done
    if [[ -n "$deleting" && "$previous" == "-k" ]]; then
        while IFS= read -r key; do
            case "$key" in
                "$current"*) COMPREPLY+=("$key") ;;
            esac
        done < <("${COMP_WORDS[0]}" __complete-keys 2>/dev/null)
    fi
}
complete -F _setup_ssh_key_delete_completion -- {{COMMAND}}
`

const zshCompletion = `# Zsh completion for setup-ssh-key deletion key names.
if ! (( $+functions[compdef] )); then
    autoload -Uz compinit
    compinit
fi

_setup_ssh_key_delete_completion() {
    local word deleting key_output
    deleting=0
    for word in "${words[@]}"; do
        if [[ "$word" == "-d" || "$word" == "--delete" ]]; then
            deleting=1
        fi
    done
    if (( deleting )) && [[ "${words[CURRENT-1]}" == "-k" ]]; then
        key_output=$("${words[1]}" __complete-keys 2>/dev/null)
        compadd -- ${(f)key_output}
    fi
}
compdef _setup_ssh_key_delete_completion {{COMMAND}}
`

const fishCompletion = `# Fish completion for setup-ssh-key deletion key names.
function __setup_ssh_key_delete_key_expected
    set -l tokens (commandline -opc)
    set -l deleting 0
    for token in $tokens
        if test "$token" = -d; or test "$token" = --delete
            set deleting 1
        end
    end
    test $deleting -eq 1; or return 1
    test (count $tokens) -gt 0; or return 1
    test "$tokens[-1]" = -k
end

function __setup_ssh_key_delete_candidates
    set -l tokens (commandline -opc)
    test (count $tokens) -gt 0; or return
    command $tokens[1] __complete-keys 2>/dev/null
end

complete -c {{COMMAND}} -n __setup_ssh_key_delete_key_expected -a '(__setup_ssh_key_delete_candidates)'
`

const powershellCompletion = `# PowerShell completion for setup-ssh-key deletion key names.
Register-ArgumentCompleter -CommandName {{COMMAND}} -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $elements = @($commandAst.CommandElements | ForEach-Object { $_.Value })
    if ($elements.Count -eq 0) { return }
    if (-not (($elements -contains '-d') -or ($elements -contains '--delete'))) { return }

    $keyExpected = $elements[-1] -eq '-k'
    if (-not $keyExpected -and $elements.Count -ge 2) {
        $keyExpected = $elements[-2] -eq '-k'
    }
    if (-not $keyExpected) { return }

    $commandName = $elements[0]
    & $commandName __complete-keys 2>$null |
        Where-Object { $_.StartsWith($wordToComplete, [System.StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
}
`

func (a *app) runCompletion(args []string) int {
	if len(args) != 1 {
		a.fail("completion requires one shell name: bash, zsh, fish, or powershell")
		return 2
	}
	script, err := completionScript(args[0], programName())
	if err != nil {
		a.fail("%v", err)
		return 2
	}
	fmt.Fprint(a.out, script)
	return 0
}

func (a *app) runCompletionKeys(args []string) int {
	if len(args) != 0 {
		return 2
	}
	keyDir := os.Getenv("KEY_DIR")
	if keyDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return 0
		}
		keyDir = filepath.Join(home, ".ssh")
	}
	if validateKeyDir(keyDir) != nil {
		return 0
	}
	names, err := deletableKeyNames(keyDir)
	if err != nil {
		return 0
	}
	for _, name := range names {
		fmt.Fprintln(a.out, name)
	}
	return 0
}

func completionScript(shell, commandName string) (string, error) {
	var template, quotedCommand string
	switch shell {
	case "bash":
		template, quotedCommand = bashCompletion, shellSingleQuote(commandName)
	case "zsh":
		template, quotedCommand = zshCompletion, shellSingleQuote(commandName)
	case "fish":
		template, quotedCommand = fishCompletion, shellSingleQuote(commandName)
	case "powershell", "pwsh":
		template, quotedCommand = powershellCompletion, powershellSingleQuote(commandName)
	default:
		return "", fmt.Errorf("unsupported completion shell %q; use bash, zsh, fish, or powershell", shell)
	}
	return strings.ReplaceAll(template, "{{COMMAND}}", quotedCommand), nil
}

func deletableKeyNames(keyDir string) ([]string, error) {
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pub") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".pub")
		if validateKeyName(name) != nil {
			continue
		}
		path := filepath.Join(keyDir, entry.Name())
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		publicKey, err := readPublicKey(path)
		if err != nil {
			continue
		}
		if _, err := publicKeyIdentity(publicKey); err != nil {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func powershellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
