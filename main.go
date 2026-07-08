// Command git-secret (invoked as `git secret <command>`) transparently
// encrypts pattern-matched files in a git repository. main.go only parses
// arguments, maps errors to exit codes, and formats output; all behavior
// lives in internal/cli so it can be tested without a subprocess.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/OpScaleHub/git-secret/internal/cli"
	"github.com/OpScaleHub/git-secret/internal/keybackend"
)

const helpText = `git-secret - transparent repo encryption for git

Usage: git secret <command> [args]

Commands:
  init [pattern...]   Bootstrap: write .repo-enc.yml, generate a key if
                       needed, and install git hooks. Patterns default to
                       "secrets/**" if none are given. Safe to re-run.
  status               Show which config-matched files are currently
                       plaintext vs encrypted in the working tree.
  lock                 Encrypt every config-matched file in place
                       (end of session).
  unlock               Decrypt every config-matched file in place
                       (start of session).
  encrypt <path...>    Encrypt specific files in place.
  decrypt <path...>    Decrypt specific files in place.
  rotate-keys          Generate a new key and re-encrypt every
                       config-matched file under it.
  verify               Check that every config-matched file committed at
                       HEAD is actually encrypted (exit 3 if not).
  hook <name>          Internal: invoked by the installed git hooks
                       (pre-commit, post-checkout, post-merge, pre-push).
  help                 Show this help.

Exit codes: 0 ok, 1 error, 2 key unavailable, 3 verify found plaintext in history.
`

// Exit codes, referenced by the installed hooks and documented above.
const (
	exitOK          = 0
	exitError       = 1
	exitKeyMissing  = 2
	exitVerifyFound = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Print(helpText)
		return exitError
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(helpText)
		return exitOK
	case "init":
		return cmdInit(args[1:])
	case "status":
		return cmdStatus()
	case "lock":
		return cmdLockUnlock("Encrypted", (*cli.Context).Lock)
	case "unlock":
		return cmdLockUnlock("Decrypted", (*cli.Context).Unlock)
	case "encrypt":
		return cmdEncryptDecrypt("Encrypted", args[1:], (*cli.Context).EncryptPaths)
	case "decrypt":
		return cmdEncryptDecrypt("Decrypted", args[1:], (*cli.Context).DecryptPaths)
	case "rotate-keys":
		return cmdRotateKeys()
	case "verify":
		return cmdVerify()
	case "hook":
		return cmdHook(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", args[0])
		fmt.Print(helpText)
		return exitError
	}
}

func cmdInit(patterns []string) int {
	result, err := cli.Init(patterns)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Initialized repo-enc: config at %s\n", result.ConfigPath)
	if result.GeneratedKey {
		fmt.Println("Generated a new encryption key.")
		if result.KeyExportVar != "" {
			fmt.Printf("This key backend can't store the key for you — export it now:\n  export %s=%s\n", result.KeyExportVar, result.KeyExportHex)
		}
	}
	fmt.Printf("Installed hooks: %s\n", strings.Join(result.HooksInstalled, ", "))
	return exitOK
}

func cmdStatus() int {
	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	states, err := ctx.Status()
	if err != nil {
		return fail(err)
	}
	if len(states) == 0 {
		fmt.Println("No files match the configured patterns.")
		return exitOK
	}
	for _, s := range states {
		fmt.Printf("  %-10s %s\n", s.State, s.Path)
	}
	return exitOK
}

func cmdLockUnlock(verb string, fn func(*cli.Context) ([]string, error)) int {
	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	touched, err := fn(ctx)
	if err != nil {
		return fail(err)
	}
	reportTouched(verb, touched)
	return exitOK
}

func cmdEncryptDecrypt(verb string, paths []string, fn func(*cli.Context, []string) ([]string, error)) int {
	if len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "Error: at least one file path is required\n")
		return exitError
	}
	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	touched, err := fn(ctx, paths)
	if err != nil {
		return fail(err)
	}
	reportTouched(verb, touched)
	return exitOK
}

func cmdRotateKeys() int {
	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	result, err := ctx.RotateKeys()
	if result != nil && result.KeyExportHex != "" {
		fmt.Printf("New key generated — export it now, the old key will no longer be used:\n  export %s=%s\n", result.KeyExportVar, result.KeyExportHex)
	}
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Rotated %d file(s) to a new key.\n", len(result.RotatedFiles))
	return exitOK
}

func cmdVerify() int {
	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	problems, err := ctx.Verify()
	if err != nil {
		return fail(err)
	}
	if len(problems) > 0 {
		fmt.Fprintln(os.Stderr, "verify: found plaintext committed at HEAD for:")
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
		return exitVerifyFound
	}
	fmt.Println("verify: OK - all matched files are encrypted at HEAD.")
	return exitOK
}

func cmdHook(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: 'hook' requires a hook name")
		return exitError
	}
	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	var hookErr error
	switch args[0] {
	case "pre-commit":
		hookErr = ctx.HookPreCommit()
	case "post-checkout":
		hookErr = ctx.HookPostCheckout()
	case "post-merge":
		hookErr = ctx.HookPostMerge()
	case "pre-push":
		hookErr = ctx.HookPrePush()
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown hook %q\n", args[0])
		return exitError
	}
	if hookErr != nil {
		return fail(hookErr)
	}
	return exitOK
}

func reportTouched(verb string, paths []string) {
	if len(paths) == 0 {
		fmt.Println("Nothing to do.")
		return
	}
	fmt.Printf("%s %d file(s):\n", verb, len(paths))
	for _, p := range paths {
		fmt.Printf("  %s\n", p)
	}
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	if errors.Is(err, keybackend.ErrKeyNotFound) {
		return exitKeyMissing
	}
	return exitError
}
