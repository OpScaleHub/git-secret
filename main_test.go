package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/crypto"
)

// buildBinary compiles the current source tree once per test run and
// returns the path to the resulting executable, so these tests exercise
// exactly what a user would run — not internal/cli's Go API directly.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "git-secret")
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
