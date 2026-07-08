// Command git-secret (invoked as `git secret <command>`) transparently
// encrypts pattern-matched files in a git repository. main.go only parses
// arguments, maps errors to exit codes, and formats output; all behavior
// lives in internal/cli so it can be tested without a subprocess.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/OpScaleHub/git-secret/internal/cli"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
	"github.com/OpScaleHub/git-secret/internal/keybackend"
)

// version is stamped at build time via:
//
//	go build -ldflags "-X main.version=v1.2.3" .
//
// A plain `go build .` leaves it at "dev"; cmdVersion falls back to Go's
// own build info (module version/vcs revision) in that case.
var version = "dev"

const helpText = `git-secret - transparent repo encryption for git

Usage: git secret <command> [args]

Commands:
  init [pattern...]    Bootstrap: write .repo-enc.yml, generate a key if
                       needed, and install git hooks. Patterns default to
                       "secrets/**" if none are given. Safe to re-run.
                         --key-backend file|env|gpg   (default: file)
                         --gpg-recipient <fingerprint> (repeatable; with
                           --key-backend gpg and none given, picks
                           interactively from your local GPG keys)
  status               Show which config-matched files are currently
                       plaintext vs encrypted in the working tree (and,
                       for the gpg backend, who currently has access).
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
  adduser [recipient]  gpg backend only: grant a GPG recipient access
                       (cheap -- re-wraps the existing key, no file
                       re-encryption). Omit the argument to pick from
                       your local public keyring interactively.
  removeuser <recipient>
                       gpg backend only: revoke a recipient and rotate
                       to a brand new key (a removed recipient already
                       saw the old one, so this re-encrypts every file).
  hook <name>          Internal: invoked by the installed git hooks
                       (pre-commit, post-checkout, post-merge, pre-push).
  version              Show version information.
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
	case "version", "-v", "--version":
		return cmdVersion()
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
	case "adduser":
		return cmdAddUser(args[1:])
	case "removeuser":
		return cmdRemoveUser(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", args[0])
		fmt.Print(helpText)
		return exitError
	}
}

// cmdVersion prints the release version when this binary was built with
// -ldflags, or falls back to Go's own build info (module version, VCS
// revision/dirty state) for a plain `go build .`.
func cmdVersion() int {
	v := version
	var commit, buildTime string
	dirty := false
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				commit = s.Value
			case "vcs.time":
				buildTime = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
	}
	fmt.Printf("git-secret %s\n", v)
	if commit != "" {
		if len(commit) > 12 {
			commit = commit[:12]
		}
		if dirty {
			commit += "-dirty"
		}
		fmt.Printf("  commit:  %s\n", commit)
	}
	if buildTime != "" {
		fmt.Printf("  built:   %s\n", buildTime)
	}
	fmt.Printf("  go:      %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return exitOK
}

// stringSliceFlag implements flag.Value for a repeatable string flag,
// e.g. --gpg-recipient a --gpg-recipient b.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// isTerminal reports whether f is an interactive terminal, so a prompt
// that would otherwise block forever on Scan() can fail fast instead
// (e.g. init run from a script with redirected/empty stdin).
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	keyBackend := fs.String("key-backend", "", "key backend: file, env, or gpg (default: file)")
	var recipients stringSliceFlag
	fs.Var(&recipients, "gpg-recipient", "GPG recipient fingerprint (repeatable)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitError
	}
	patterns := fs.Args()

	recips := []string(recipients)
	if *keyBackend == "gpg" && len(recips) == 0 {
		if !isTerminal(os.Stdin) {
			fmt.Fprintln(os.Stderr, "Error: --key-backend gpg needs at least one --gpg-recipient in a non-interactive session")
			return exitError
		}
		if !gpgutil.Available() {
			fmt.Fprintf(os.Stderr, "Error: %v\n", gpgutil.ErrNotInstalled)
			return exitError
		}
		keys, err := gpgutil.ListSecretKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitError
		}
		picked, err := cli.PickGPGRecipient(os.Stdin, os.Stdout, keys)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitError
		}
		recips = []string{picked}
	}

	result, err := cli.Init(cli.InitOptions{Patterns: patterns, KeyBackend: *keyBackend, GPGRecipients: recips})
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Initialized repo-enc: config at %s\n", result.ConfigPath)
	if result.GeneratedKey {
		fmt.Println("Generated a new encryption key.")
		if result.KeyExportVar != "" {
			fmt.Printf("This key backend can't store the key for you — export it now:\n  export %s=%s\n", result.KeyExportVar, result.KeyExportHex)
		}
		if result.KeyIsCommittable {
			fmt.Printf("Commit %s along with .repo-enc.yml — it's safe to commit (only a matching GPG secret key can unwrap it).\n", result.KeySource)
		}
	}
	fmt.Printf("Installed hooks: %s\n", strings.Join(result.HooksInstalled, ", "))
	return exitOK
}

func cmdAddUser(args []string) int {
	var recipient string
	if len(args) > 0 {
		recipient = args[0]
	}
	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	if recipient == "" {
		if !isTerminal(os.Stdin) {
			fmt.Fprintln(os.Stderr, "Error: 'adduser' needs a recipient argument in a non-interactive session")
			return exitError
		}
		if !gpgutil.Available() {
			fmt.Fprintf(os.Stderr, "Error: %v\n", gpgutil.ErrNotInstalled)
			return exitError
		}
		keys, err := gpgutil.ListPublicKeys("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitError
		}
		picked, err := cli.PickGPGRecipient(os.Stdin, os.Stdout, keys)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitError
		}
		recipient = picked
	}
	result, err := ctx.AddUser(recipient)
	if err != nil {
		return fail(err)
	}
	if result.AlreadyPresent {
		fmt.Printf("%s already has access.\n", result.Recipient)
		return exitOK
	}
	fmt.Printf("Added %s.\n", result.Recipient)
	fmt.Printf("Commit .repo-enc.yml and %s.\n", ctx.Config.KeySource)
	return exitOK
}

func cmdRemoveUser(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: 'removeuser' requires a recipient argument")
		return exitError
	}
	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	result, err := ctx.RemoveUser(args[0])
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Removed %s. Rotated %d file(s) to a new key.\n", result.Recipient, len(result.RotateResult.RotatedFiles))
	fmt.Println("Commit the changes.")
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
		hidden := ""
		if s.Hidden {
			hidden = "  (hidden from git status)"
		}
		fmt.Printf("  %-10s %s%s\n", s.State, s.Path, hidden)
	}
	if ctx.Config.KeyBackend == "gpg" {
		fmt.Println("GPG recipients:")
		for _, r := range ctx.Config.GPGRecipients {
			fmt.Printf("  %s\n", r)
		}
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
	if verb == "Decrypted" && len(touched) > 0 {
		fmt.Println("git status will stay quiet about these while you view them.")
		fmt.Println("If you edit one, run `git secret lock` before `git add` — a plain `git add` on a still-unlocked file will be refused by git.")
	}
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
