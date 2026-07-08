package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/OpScaleHub/git-secret/internal/gitutil"
)

// binaryName is the executable hooks shell out to. It must be on PATH,
// same as the `git secret <cmd>` invocation itself.
const binaryName = "git-secret"

// hookMarker identifies a hook file as one we manage, so re-running
// InstallHooks is idempotent and so a pre-existing, unrelated hook is
// detected and preserved rather than clobbered.
const hookMarker = "managed-by: repo-enc"

// SkipEnvVars are environment variables that make every installed hook
// exit 0 immediately without running, for CI and other automation.
var SkipEnvVars = []string{"SECRETIZE_SKIP_HOOKS", "CI"}

// InstallHooks writes wrapper scripts for HookNames into the repo's hooks
// directory (respecting core.hooksPath). Both a POSIX shell script (the
// one git actually executes, including under Git for Windows) and a
// PowerShell variant (for teams whose tooling invokes hooks through
// PowerShell directly) are written for each hook name.
//
// Non-destructive: if a hook file already exists and isn't one we wrote
// previously, it's preserved as "<name>.local" and chained — our script
// runs it first and aborts if it fails, then proceeds with its own logic.
func InstallHooks(repoRoot string) ([]string, error) {
	dir, err := gitutil.HooksDir(repoRoot)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("hook install: create hooks dir: %w", err)
	}

	var installed []string
	for _, name := range HookNames {
		path := filepath.Join(dir, name)
		if existing, err := os.ReadFile(path); err == nil {
			if !bytes.Contains(existing, []byte(hookMarker)) {
				localPath := filepath.Join(dir, name+".local")
				if err := os.Rename(path, localPath); err != nil {
					return installed, fmt.Errorf("hook install: preserve existing %s hook: %w", name, err)
				}
				os.Chmod(localPath, 0o755)
			}
		} else if !os.IsNotExist(err) {
			return installed, fmt.Errorf("hook install: read existing %s hook: %w", name, err)
		}

		if err := os.WriteFile(path, []byte(shHookScript(name)), 0o755); err != nil {
			return installed, fmt.Errorf("hook install: write %s: %w", name, err)
		}
		psPath := filepath.Join(dir, name+".ps1")
		if err := os.WriteFile(psPath, []byte(psHookScript(name)), 0o755); err != nil {
			return installed, fmt.Errorf("hook install: write %s.ps1: %w", name, err)
		}
		installed = append(installed, name)
	}
	return installed, nil
}

func shHookScript(name string) string {
	return fmt.Sprintf(`#!/bin/sh
# %s
# Regenerate with: %s init  (do not edit by hand — edits are lost on re-install)
if [ -n "$SECRETIZE_SKIP_HOOKS" ] || [ -n "$CI" ]; then
  exit 0
fi
dir="$(dirname "$0")"
if [ -x "$dir/%s.local" ]; then
  "$dir/%s.local" "$@" || exit $?
fi
exec %s hook %s "$@"
`, hookMarker, binaryName, name, name, binaryName, name)
}

func psHookScript(name string) string {
	return fmt.Sprintf(`# %s
# Regenerate with: %s init  (do not edit by hand — edits are lost on re-install)
if ($env:SECRETIZE_SKIP_HOOKS -or $env:CI) { exit 0 }
$localHook = Join-Path $PSScriptRoot "%s.local.ps1"
if (Test-Path $localHook) {
    & $localHook @args
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& %s hook %s @args
exit $LASTEXITCODE
`, hookMarker, binaryName, name, binaryName, name)
}
