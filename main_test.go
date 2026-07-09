package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/OpScaleHub/git-secret/crypto"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// shortTempDir returns a short-path temp directory suitable for
// GNUPGHOME. t.TempDir() on macOS lives under a long
// /var/folders/.../T/<test name>/001 path, and gpg-agent's Unix domain
// socket (created inside GNUPGHOME) can exceed AF_UNIX's ~104-byte
// sun_path limit there ("File name too long" / "IPC connect call
// failed") — a real GnuPG-on-macOS gotcha, unrelated to this feature.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gnupg-test-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// buildBinary compiles the current source tree once per test run and
// returns the path to the resulting executable, so these tests exercise
// exactly what a user would run — not internal/cli's Go API directly.
// Windows requires the .exe extension: unlike Unix, Go does not append
// it automatically for an explicit -o name, and without it neither
// os/exec nor cmd.exe/PowerShell will resolve the file as executable.
func buildBinary(t *testing.T) string {
	t.Helper()
	name := "git-secret"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build git-secret: %v\n%s", err, out)
	}
	return bin
}

func runBin(t *testing.T, bin, dir string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return out.String(), errBuf.String(), ee.ExitCode()
		}
		t.Fatalf("run git-secret %s: %v", strings.Join(args, " "), err)
	}
	return out.String(), errBuf.String(), 0
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// runGitTriggeringHooks is like runGit but strips CI/SECRETIZE_SKIP_HOOKS
// from the child's environment first. Installed hooks intentionally
// no-op under those vars (so CI systems don't trip them unexpectedly),
// but this repo's own test suite runs under CI=true on GitHub Actions and
// needs the real installed hook to fire to test it.
func runGitTriggeringHooks(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "CI=") || strings.HasPrefix(e, "SECRETIZE_SKIP_HOOKS=") {
			continue
		}
		env = append(env, e)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test")
	return dir
}

// withBinOnPath prepends bin's directory to PATH for the current process,
// restoring the previous value on test cleanup. Hook scripts installed by
// `init` invoke the binary by name, so it must be resolvable this way.
func withBinOnPath(t *testing.T, bin string) {
	t.Helper()
	old := os.Getenv("PATH")
	os.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+old)
	t.Cleanup(func() { os.Setenv("PATH", old) })
}

func TestCLIHelpAndUnknownCommand(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	out, _, code := runBin(t, bin, dir, "help")
	if code != 0 || !strings.Contains(out, "Usage: git secret") {
		t.Fatalf("help: code=%d out=%q", code, out)
	}

	_, _, code = runBin(t, bin, dir)
	if code != 1 {
		t.Fatalf("no args: code=%d, want 1", code)
	}

	_, stderr, code := runBin(t, bin, dir, "bogus-command")
	if code != 1 || !strings.Contains(stderr, "Unknown command") {
		t.Fatalf("unknown command: code=%d stderr=%q", code, stderr)
	}
}

func TestCLIVersion(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	for _, arg := range []string{"version", "--version", "-v"} {
		out, stderr, code := runBin(t, bin, dir, arg)
		if code != 0 {
			t.Fatalf("%s: code=%d stderr=%q", arg, code, stderr)
		}
		if !strings.Contains(out, "git-secret") {
			t.Fatalf("%s: output missing name: %q", arg, out)
		}
		if !strings.Contains(out, "go:") {
			t.Fatalf("%s: output missing go runtime line: %q", arg, out)
		}
	}
}

func TestCLIInitLockStatusUnlockCycle(t *testing.T) {
	bin := buildBinary(t)
	withBinOnPath(t, bin)
	repo := initGitRepo(t)

	out, _, code := runBin(t, bin, repo, "init", "secrets/**")
	if code != 0 {
		t.Fatalf("init: code=%d out=%q", code, out)
	}
	if _, err := os.Stat(filepath.Join(repo, ".repo-enc.yml")); err != nil {
		t.Fatalf("config not created: %v", err)
	}

	secretPath := filepath.Join(repo, "secrets", "db.yaml")
	os.MkdirAll(filepath.Dir(secretPath), 0o755)
	const plaintext = "password: hunter2\n"
	os.WriteFile(secretPath, []byte(plaintext), 0o644)

	out, _, code = runBin(t, bin, repo, "status")
	if code != 0 || !strings.Contains(out, "plaintext") {
		t.Fatalf("status before lock: code=%d out=%q", code, out)
	}

	out, _, code = runBin(t, bin, repo, "lock")
	if code != 0 || !strings.Contains(out, "secrets/db.yaml") {
		t.Fatalf("lock: code=%d out=%q", code, out)
	}
	data, _ := os.ReadFile(secretPath)
	if !crypto.IsEnvelope(data) {
		t.Fatalf("file not encrypted after lock: %q", data)
	}

	out, _, code = runBin(t, bin, repo, "status")
	if code != 0 || !strings.Contains(out, "encrypted") {
		t.Fatalf("status after lock: code=%d out=%q", code, out)
	}

	out, _, code = runBin(t, bin, repo, "unlock")
	if code != 0 {
		t.Fatalf("unlock: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "git secret lock") {
		t.Fatalf("unlock output missing the lock-before-git-add guidance: %q", out)
	}
	data, _ = os.ReadFile(secretPath)
	if string(data) != plaintext {
		t.Fatalf("unlock did not restore plaintext: %q", data)
	}
}

func TestCLIVerifyExitsNonZeroOnLeakedPlaintext(t *testing.T) {
	bin := buildBinary(t)
	withBinOnPath(t, bin)
	repo := initGitRepo(t)

	if _, _, code := runBin(t, bin, repo, "init", "secrets/**"); code != 0 {
		t.Fatalf("init failed")
	}
	secretPath := filepath.Join(repo, "secrets", "db.yaml")
	os.MkdirAll(filepath.Dir(secretPath), 0o755)
	os.WriteFile(secretPath, []byte("password: hunter2\n"), 0o644)

	runGit(t, repo, "add", "secrets/db.yaml")
	runGit(t, repo, "commit", "-q", "--no-verify", "-m", "leaked plaintext")

	_, stderr, code := runBin(t, bin, repo, "verify")
	if code != 3 {
		t.Fatalf("verify: code=%d, want 3; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "secrets/db.yaml") {
		t.Fatalf("verify stderr missing offending path: %q", stderr)
	}
}

func TestCLICommitThenCloneDecryptsWithSharedKey(t *testing.T) {
	bin := buildBinary(t)
	withBinOnPath(t, bin)
	repoA := initGitRepo(t)

	if _, _, code := runBin(t, bin, repoA, "init", "secrets/**"); code != 0 {
		t.Fatalf("init in repoA failed")
	}
	secretPath := filepath.Join(repoA, "secrets", "db.yaml")
	os.MkdirAll(filepath.Dir(secretPath), 0o755)
	const plaintext = "password: hunter2\n"
	os.WriteFile(secretPath, []byte(plaintext), 0o644)

	runGit(t, repoA, "add", "secrets/db.yaml")
	runGitTriggeringHooks(t, repoA, "commit", "-q", "-m", "add secret")

	if _, stderr, code := runBin(t, bin, repoA, "verify"); code != 0 {
		t.Fatalf("verify in repoA after hook-processed commit: code=%d stderr=%q", code, stderr)
	}

	keyBytes, err := os.ReadFile(filepath.Join(repoA, ".repo-enc", "key"))
	if err != nil {
		t.Fatalf("read repoA key: %v", err)
	}
	if _, err := hex.DecodeString(strings.TrimSpace(string(keyBytes))); err != nil {
		t.Fatalf("repoA key is not hex-encoded: %v", err)
	}

	repoB := filepath.Join(t.TempDir(), "clone")
	runGit(t, filepath.Dir(repoB), "clone", "-q", repoA, repoB)

	// The clone's working tree holds exactly what was committed: ciphertext.
	clonedData, err := os.ReadFile(filepath.Join(repoB, "secrets", "db.yaml"))
	if err != nil {
		t.Fatalf("read cloned secret: %v", err)
	}
	if !crypto.IsEnvelope(clonedData) {
		t.Fatalf("cloned working tree file is not ciphertext: %q", clonedData)
	}

	// Onboarding a second clone: install hooks for this checkout, then the
	// key must be transferred out-of-band (it's gitignored, never cloned).
	if _, _, code := runBin(t, bin, repoB, "init"); code != 0 {
		t.Fatalf("init in repoB (hook install) failed")
	}
	os.MkdirAll(filepath.Join(repoB, ".repo-enc"), 0o700)
	os.WriteFile(filepath.Join(repoB, ".repo-enc", "key"), keyBytes, 0o600)

	// Simulate what the installed post-checkout hook does automatically.
	if _, stderr, code := runBin(t, bin, repoB, "hook", "post-checkout"); code != 0 {
		t.Fatalf("hook post-checkout in repoB: code=%d stderr=%q", code, stderr)
	}

	data, err := os.ReadFile(filepath.Join(repoB, "secrets", "db.yaml"))
	if err != nil {
		t.Fatalf("read repoB secret after post-checkout: %v", err)
	}
	if string(data) != plaintext {
		t.Fatalf("repoB did not decrypt to original plaintext: %q", data)
	}
}

// TestPullConflictsWithUnlockedFileThenRecovers is the real end-to-end
// version of a scenario earlier only sanity-checked with raw `git`
// commands on *unchanged* content by hand -- which turned out to miss
// the actual risk. When teammate B has a file genuinely unlocked
// (working tree plaintext deliberately diverged from the committed
// ciphertext, which is the normal state the instant you run `unlock`)
// and teammate A pushes a change to that same file, B's `git pull`
// does NOT silently go stale -- it hard-fails with git's standard
// "local changes would be overwritten by merge" error, because the
// skip-worktree bit suppresses status/diff reporting but does not
// suppress git's real uncommitted-change protection during a merge.
// There is no pre-pull/pre-merge hook to intervene before this check
// runs, so it can't be engineered away -- only documented with a safe
// recovery. This test pins both halves: the conflict really happens,
// and the documented recovery really works: lock (clears skip-worktree;
// the working tree is now disposable ciphertext), discard it with our
// own hooks suppressed (git checkout -- <path> fires post-checkout even
// for a single-path restore in this git version, which would otherwise
// immediately re-decrypt what checkout just restored and reintroduce
// the exact divergence that blocks the pull), then pull.
func TestPullConflictsWithUnlockedFileThenRecovers(t *testing.T) {
	bin := buildBinary(t)
	withBinOnPath(t, bin)
	repoA := initGitRepo(t)

	if _, _, code := runBin(t, bin, repoA, "init", "secrets/**"); code != 0 {
		t.Fatalf("init in repoA failed")
	}
	secretPath := filepath.Join(repoA, "secrets", "db.yaml")
	os.MkdirAll(filepath.Dir(secretPath), 0o755)
	os.WriteFile(secretPath, []byte("password: hunter2\n"), 0o644)
	runGit(t, repoA, "add", "secrets/db.yaml")
	runGitTriggeringHooks(t, repoA, "commit", "-q", "-m", "add secret")

	keyBytes, err := os.ReadFile(filepath.Join(repoA, ".repo-enc", "key"))
	if err != nil {
		t.Fatalf("read repoA key: %v", err)
	}

	repoB := filepath.Join(t.TempDir(), "clone")
	runGit(t, filepath.Dir(repoB), "clone", "-q", repoA, repoB)
	if _, _, code := runBin(t, bin, repoB, "init"); code != 0 {
		t.Fatalf("init in repoB (hook install) failed")
	}
	os.MkdirAll(filepath.Join(repoB, ".repo-enc"), 0o700)
	os.WriteFile(filepath.Join(repoB, ".repo-enc", "key"), keyBytes, 0o600)
	if _, stderr, code := runBin(t, bin, repoB, "hook", "post-checkout"); code != 0 {
		t.Fatalf("hook post-checkout in repoB: code=%d stderr=%q", code, stderr)
	}

	// B now has their own decrypted, skip-worktree'd copy with no local
	// edits -- confirm the starting state before A changes anything.
	data, _ := os.ReadFile(filepath.Join(repoB, "secrets", "db.yaml"))
	if string(data) != "password: hunter2\n" {
		t.Fatalf("repoB initial content wrong: %q", data)
	}
	if out := runGit(t, repoB, "status", "--short"); strings.Contains(out, "secrets/db.yaml") {
		t.Fatalf("repoB should be clean before the pull, got: %q", out)
	}

	// A rotates the secret, following the documented edit flow:
	// edit -> lock -> add -> commit.
	os.WriteFile(secretPath, []byte("password: hunter3\n"), 0o644)
	if _, _, code := runBin(t, bin, repoA, "lock"); code != 0 {
		t.Fatalf("lock in repoA failed")
	}
	runGit(t, repoA, "add", "secrets/db.yaml")
	runGitTriggeringHooks(t, repoA, "commit", "-q", "-m", "rotate password")

	// B's plain `git pull` must fail loudly, not silently stay stale.
	cmd := exec.Command("git", "pull", "-q")
	cmd.Dir = repoB
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected `git pull` to conflict with B's unlocked (diverged) file, but it succeeded: %s", out)
	}
	if !strings.Contains(string(out), "would be overwritten") {
		t.Fatalf("expected git's local-changes-would-be-overwritten error, got: %s", out)
	}

	// Documented recovery: lock (clears skip-worktree; the working tree
	// is now disposable ciphertext, not the secret itself), then
	// discard it back to what's committed with our own hooks
	// suppressed -- `git checkout -- <path>` fires post-checkout in
	// this git version even for a single-path restore, which would
	// otherwise immediately re-decrypt what checkout just restored and
	// put us right back in a diverged, pull-blocking state -- then pull.
	if _, _, code := runBin(t, bin, repoB, "lock"); code != 0 {
		t.Fatalf("lock in repoB failed")
	}
	checkoutCmd := exec.Command("git", "checkout", "--", "secrets/db.yaml")
	checkoutCmd.Dir = repoB
	checkoutCmd.Env = append(os.Environ(), "SECRETIZE_SKIP_HOOKS=1")
	if out, err := checkoutCmd.CombinedOutput(); err != nil {
		t.Fatalf("checkout -- secrets/db.yaml: %v\n%s", err, out)
	}
	runGitTriggeringHooks(t, repoB, "pull", "-q")

	data, err = os.ReadFile(filepath.Join(repoB, "secrets", "db.yaml"))
	if err != nil {
		t.Fatalf("read repoB secret after recovery+pull: %v", err)
	}
	if string(data) != "password: hunter3\n" {
		t.Fatalf("repoB did not refresh to the rotated password after recovery: %q", data)
	}
	if out := runGit(t, repoB, "status", "--short"); strings.Contains(out, "secrets/db.yaml") {
		t.Fatalf("repoB should be clean after recovery, got: %q", out)
	}
}

func TestCLIRotateKeysThenUnlockAcrossBinary(t *testing.T) {
	bin := buildBinary(t)
	withBinOnPath(t, bin)
	repo := initGitRepo(t)

	if _, _, code := runBin(t, bin, repo, "init", "secrets/**"); code != 0 {
		t.Fatalf("init failed")
	}
	secretPath := filepath.Join(repo, "secrets", "db.yaml")
	os.MkdirAll(filepath.Dir(secretPath), 0o755)
	const plaintext = "password: hunter2\n"
	os.WriteFile(secretPath, []byte(plaintext), 0o644)

	if _, _, code := runBin(t, bin, repo, "lock"); code != 0 {
		t.Fatalf("lock failed")
	}
	keyBefore, _ := os.ReadFile(filepath.Join(repo, ".repo-enc", "key"))

	out, _, code := runBin(t, bin, repo, "rotate-keys")
	if code != 0 {
		t.Fatalf("rotate-keys: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "Rotated 1 file") {
		t.Fatalf("rotate-keys output unexpected: %q", out)
	}
	keyAfter, _ := os.ReadFile(filepath.Join(repo, ".repo-enc", "key"))
	if string(keyBefore) == string(keyAfter) {
		t.Fatalf("key file unchanged after rotate-keys")
	}

	if _, _, code := runBin(t, bin, repo, "unlock"); code != 0 {
		t.Fatalf("unlock after rotate-keys failed")
	}
	data, _ := os.ReadFile(secretPath)
	if string(data) != plaintext {
		t.Fatalf("unlock after rotate-keys gave wrong content: %q", data)
	}
}

func TestCLIInitGPGBackendNonInteractive(t *testing.T) {
	if !gpgutil.Available() {
		t.Skip("gpg not installed")
	}
	if runtime.GOOS == "windows" {
		// gpg-agent is unreliably reachable on GitHub's windows-latest
		// runners for unattended key generation — a CI environment
		// quirk, not a limitation of the feature itself.
		t.Skip("gpg-agent unreliable on windows CI runners")
	}
	bin := buildBinary(t)
	withBinOnPath(t, bin)
	repo := initGitRepo(t)

	t.Setenv("GNUPGHOME", shortTempDir(t))
	genCmd := exec.Command(gpgutil.Binary, "--batch", "--passphrase", "", "--quick-generate-key", "Test <test@example.com>", "default", "default", "never")
	if out, err := genCmd.CombinedOutput(); err != nil {
		t.Fatalf("generate test gpg key: %v: %s", err, out)
	}
	keys, err := gpgutil.ListSecretKeys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListSecretKeys: keys=%v err=%v", keys, err)
	}
	fpr := keys[0].Fingerprint

	out, stderr, code := runBin(t, bin, repo, "init", "--key-backend", "gpg", "--gpg-recipient", fpr, "secrets/**")
	if code != 0 {
		t.Fatalf("init --key-backend gpg: code=%d out=%q stderr=%q", code, out, stderr)
	}
	if !strings.Contains(out, "safe to commit") {
		t.Fatalf("init output missing commit guidance: %q", out)
	}

	secretPath := filepath.Join(repo, "secrets", "db.yaml")
	os.MkdirAll(filepath.Dir(secretPath), 0o755)
	os.WriteFile(secretPath, []byte("password: hunter2\n"), 0o644)

	if _, _, code := runBin(t, bin, repo, "lock"); code != 0 {
		t.Fatalf("lock failed")
	}
	locked, _ := os.ReadFile(secretPath)
	if !crypto.IsEnvelope(locked) {
		t.Fatalf("file not encrypted after lock: %q", locked)
	}

	if _, _, code := runBin(t, bin, repo, "unlock"); code != 0 {
		t.Fatalf("unlock failed")
	}
	unlocked, _ := os.ReadFile(secretPath)
	if string(unlocked) != "password: hunter2\n" {
		t.Fatalf("unlock gave wrong content: %q", unlocked)
	}

	// The wrapped key file must not have been gitignored.
	gitignore, _ := os.ReadFile(filepath.Join(repo, ".gitignore"))
	if strings.Contains(string(gitignore), ".repo-enc/key.gpg") {
		t.Fatalf("gpg key blob should not be gitignored: %q", gitignore)
	}
}
