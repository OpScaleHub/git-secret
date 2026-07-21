package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/gitutil"
)

// newTestRepo creates a scratch git repo, chdirs the test into it (t.Chdir
// restores the previous cwd automatically), and returns its root path.
func newTestRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// Resolve symlinks (macOS/CI temp dirs are often under /tmp -> /private/tmp)
	// so paths returned by `git rev-parse --show-toplevel` compare equal.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.com")
	runGit(t, root, "config", "user.name", "Test")
	t.Chdir(root)
	return root
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

// commitInitConfig stages and commits the config/gitignore files Init
// wrote. Verify/HookPrePush load .repo-enc.yml from the revision being
// checked, not from disk, so they have nothing to enforce until the
// config itself is committed — real usage always commits it immediately
// after `init`, and test fixtures need to mirror that.
//
// --no-verify: this package tests HookPreCommit et al. directly as Go
// functions (see commitViaHook in skipworktree_test.go), not through the
// real installed hook script -- that script `exec`s the `git-secret`
// binary by name on PATH, which nothing in this package builds/installs
// (unlike main_test.go's black-box tests, which do). Neither
// .repo-enc.yml nor .gitignore is pattern-matched content anyway, so
// there's nothing for the real hook to do here even if it did run.
func commitInitConfig(t *testing.T, root string) {
	t.Helper()
	runGit(t, root, "add", ".repo-enc.yml", ".gitignore")
	runGit(t, root, "commit", "-q", "--no-verify", "-m", "repo-enc: init")
}

func writeRepoFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	abs := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", relPath, err)
	}
}

func TestInitCreatesConfigKeyAndHooks(t *testing.T) {
	root := newTestRepo(t)

	result, err := Init(InitOptions{Patterns: []string{"secrets/**"}})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !result.GeneratedKey {
		t.Errorf("expected Init to generate a key on first run")
	}
	if _, err := os.Stat(result.ConfigPath); err != nil {
		t.Errorf("config file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".repo-enc", "key")); err != nil {
		t.Errorf("key file missing: %v", err)
	}
	gitignore, _ := os.ReadFile(filepath.Join(root, ".gitignore"))
	if !strings.Contains(string(gitignore), ".repo-enc/key") {
		t.Errorf(".gitignore does not cover the key file: %q", gitignore)
	}

	hooksDir, err := gitutil.HooksDir(root)
	if err != nil {
		t.Fatalf("HooksDir: %v", err)
	}
	for _, name := range HookNames {
		data, err := os.ReadFile(filepath.Join(hooksDir, name))
		if err != nil {
			t.Errorf("hook %s not installed: %v", name, err)
			continue
		}
		if !strings.Contains(string(data), hookMarker) {
			t.Errorf("hook %s missing marker", name)
		}
		if strings.Contains(string(data), "$CI") {
			t.Errorf("hook %s still honors ambient $CI as an implicit skip bypass", name)
		}
		if _, err := os.Stat(filepath.Join(hooksDir, name+".ps1")); err != nil {
			t.Errorf("PowerShell variant for %s missing: %v", name, err)
		}
	}

	// Re-running Init must be idempotent: same config path, key untouched.
	keyBefore, _ := os.ReadFile(filepath.Join(root, ".repo-enc", "key"))
	result2, err := Init(InitOptions{Patterns: []string{"ignored-on-second-run/**"}})
	if err != nil {
		t.Fatalf("second Init: %v", err)
	}
	if result2.GeneratedKey {
		t.Errorf("second Init should not regenerate an existing key")
	}
	keyAfter, _ := os.ReadFile(filepath.Join(root, ".repo-enc", "key"))
	if string(keyBefore) != string(keyAfter) {
		t.Errorf("key changed across idempotent Init calls")
	}
}

func TestLockUnlockRoundTrip(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	touched, err := ctx.Lock()
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if len(touched) != 1 || touched[0] != "secrets/db.yaml" {
		t.Fatalf("Lock touched = %v, want [secrets/db.yaml]", touched)
	}
	data, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if strings.Contains(string(data), "hunter2") {
		t.Fatalf("file still plaintext after Lock: %q", data)
	}

	// Locking again is a no-op (idempotent).
	touched, err = ctx.Lock()
	if err != nil {
		t.Fatalf("second Lock: %v", err)
	}
	if len(touched) != 0 {
		t.Fatalf("second Lock should touch nothing, got %v", touched)
	}

	touched, err = ctx.Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if len(touched) != 1 {
		t.Fatalf("Unlock touched = %v, want 1 file", touched)
	}
	data, _ = os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if string(data) != "password: hunter2\n" {
		t.Fatalf("Unlock did not restore original content, got %q", data)
	}
}

func TestStatusReportsStates(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/a.yaml", "a")
	writeRepoFile(t, root, "secrets/b.yaml", "b")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.EncryptPaths([]string{"secrets/a.yaml"}); err != nil {
		t.Fatalf("EncryptPaths: %v", err)
	}

	states, err := ctx.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	got := map[string]string{}
	for _, s := range states {
		got[s.Path] = s.State
	}
	if got["secrets/a.yaml"] != StateEncrypted {
		t.Errorf("secrets/a.yaml state = %q, want %q", got["secrets/a.yaml"], StateEncrypted)
	}
	if got["secrets/b.yaml"] != StatePlaintext {
		t.Errorf("secrets/b.yaml state = %q, want %q", got["secrets/b.yaml"], StatePlaintext)
	}
}

func TestHookPreCommitEncryptsIndexOnlyLeavesWorkingTreePlaintext(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	commitInitConfig(t, root)
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	runGit(t, root, "add", "secrets/db.yaml")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := ctx.HookPreCommit(); err != nil {
		t.Fatalf("HookPreCommit: %v", err)
	}

	staged, err := gitutil.ReadStaged(root, "secrets/db.yaml")
	if err != nil {
		t.Fatalf("ReadStaged: %v", err)
	}
	if strings.Contains(string(staged), "hunter2") {
		t.Fatalf("staged content is still plaintext: %q", staged)
	}

	working, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if string(working) != "password: hunter2\n" {
		t.Fatalf("working tree file was modified by pre-commit hook: %q", working)
	}

	runGit(t, root, "commit", "-q", "--no-verify", "-m", "add secret")
	problems, err := ctx.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("Verify found problems after hook-processed commit: %v", problems)
	}
}

func TestVerifyAndPrePushDetectLeakedPlaintext(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	commitInitConfig(t, root)
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	// Commit with --no-verify to simulate a bypassed pre-commit hook (the
	// exact scenario HookPrePush exists to catch).
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "--no-verify", "-m", "oops committed plaintext")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	problems, err := ctx.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(problems) != 1 || !strings.HasPrefix(problems[0], "secrets/db.yaml") {
		t.Fatalf("Verify problems = %v, want a single problem for secrets/db.yaml", problems)
	}

	if err := ctx.HookPrePush(strings.NewReader("")); err == nil {
		t.Fatalf("expected HookPrePush to block push on leaked plaintext")
	}
}

// TestHookPrePushDetectsPlaintextInPushedRangeNotJustHEAD pins the fix
// for the exact gap issue #3 described: HEAD alone can be clean while an
// earlier commit in the range actually being pushed still carries
// plaintext. HookPrePush must read the ref-update range from stdin and
// walk it, not just check HEAD.
func TestHookPrePushDetectsPlaintextInPushedRangeNotJustHEAD(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	commitInitConfig(t, root)
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "--no-verify", "-m", "leak plaintext")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "--no-verify", "-m", "fix HEAD")
	fixedSHA := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

	// HEAD alone is clean now.
	problems, err := ctx.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("Verify at HEAD should be clean, got %v", problems)
	}

	// But the range being pushed (a fresh push to an empty remote, so
	// remote oid is all-zero per the pre-push protocol) still carries
	// the earlier leaked commit.
	stdin := strings.NewReader(fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", fixedSHA, gitutil.ZeroOID))
	if err := ctx.HookPrePush(stdin); err == nil {
		t.Fatalf("expected HookPrePush to block push: an earlier commit in the range leaked plaintext")
	} else if !strings.Contains(err.Error(), "secrets/db.yaml") {
		t.Fatalf("HookPrePush error missing offending path: %v", err)
	}
}

// TestVerifyFlagsCommittedRawFileBackendKey pins the fix for issue #4: a
// force-added raw file-backend key must always be flagged by verify,
// independent of whether it happens to also match `patterns`.
func TestVerifyFlagsCommittedRawFileBackendKey(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	commitInitConfig(t, root)

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	runGit(t, root, "add", "-f", ".repo-enc/key")
	runGit(t, root, "commit", "-q", "--no-verify", "-m", "oops, committed the raw key")

	problems, err := ctx.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	found := false
	for _, p := range problems {
		if strings.Contains(p, ".repo-enc/key") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Verify problems = %v, want one flagging the committed raw key", problems)
	}
}

// TestEncryptPathsRejectsPathEscapingRepoRoot pins the fix for issue #7
// (repro B): an explicit `encrypt`/`decrypt` CLI path must not be able to
// read or overwrite a file outside the repository via "..".
func TestEncryptPathsRejectsPathEscapingRepoRoot(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside secret\n"), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	t.Cleanup(func() { os.Remove(outside) })

	if _, err := ctx.EncryptPaths([]string{"../outside.txt"}); err == nil {
		t.Fatalf("expected EncryptPaths to reject a path escaping the repo root")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read outside file: %v", err)
	}
	if string(data) != "outside secret\n" {
		t.Fatalf("outside file was modified: %q", data)
	}
}

// TestInitRejectsKeySourceEscapingRepoRoot pins the fix for issue #7
// (repro A): a committed key_source pointing outside the repo (via ".."
// or an absolute path) must not make `init` create a key there.
func TestInitRejectsKeySourceEscapingRepoRoot(t *testing.T) {
	root := newTestRepo(t)
	writeRepoFile(t, root, ".repo-enc.yml", "version: 1\npatterns:\n  - \"secrets/**\"\nkey_backend: file\nkey_source: ../outside-key\n")

	if _, err := Init(InitOptions{}); err == nil {
		t.Fatalf("expected Init to reject a key_source escaping the repo root")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "outside-key")); err == nil {
		t.Fatalf("key was generated outside the repo root")
	}
}

// TestLockRefusesMatchedSymlink pins the fix for issue #18: a
// repo-controlled symlink under a protected pattern must not be followed
// into reading (and then encrypting the contents of) an arbitrary local
// file outside the repo.
func TestLockRefusesMatchedSymlink(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	outside := filepath.Join(filepath.Dir(root), "git-secret-outside-secret")
	if err := os.WriteFile(outside, []byte("outside-password=hunter2\n"), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	t.Cleanup(func() { os.Remove(outside) })

	if err := os.MkdirAll(filepath.Join(root, "secrets"), 0o755); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}
	linkPath := filepath.Join(root, "secrets", "leak.env")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Lock(); err == nil {
		t.Fatalf("expected Lock to refuse a symlinked matched path")
	}
	fi, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink was replaced instead of being refused")
	}
}

// TestUnlockWritesPlaintextWith0600 pins the fix for issue #9: decrypted
// plaintext must not be world/group-readable regardless of the
// ciphertext blob's own mode (an ordinary git checkout is 0644).
func TestUnlockWritesPlaintextWith0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows has no POSIX permission bits -- os.Chmod there only
		// toggles the read-only attribute, and a writable file always
		// reads back as 0666 regardless of what was requested. The fix
		// itself (WriteFileAtomic passing 0o600) is still correct/
		// best-effort there; only this exact-mode assertion doesn't
		// port.
		t.Skip("POSIX file mode bits don't apply on Windows")
	}
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, "secrets/db.yaml"), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := ctx.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	fi, err := os.Stat(filepath.Join(root, "secrets/db.yaml"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("decrypted file mode = %o, want 0600", fi.Mode().Perm())
	}
}

// TestRotateKeysGitignoresStagingKey pins the fix for issue #19: the
// raw, unwrapped staging key rotate-keys generates mid-rotation must be
// gitignored from the moment it's created, not just the promoted key —
// otherwise a `git add .` during or after a failed rotation can commit
// it.
func TestRotateKeysGitignoresStagingKey(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.RotateKeys(); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	gitignore, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	if !strings.Contains(string(gitignore), ".repo-enc/key.new") {
		t.Fatalf(".gitignore = %q, want it to cover the staging key .repo-enc/key.new", gitignore)
	}
}

func TestRotateKeysReencryptsAndInvalidatesOldKey(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	oldKey, err := ctx.Key()
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	encryptedBefore, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))

	result, err := ctx.RotateKeys()
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if len(result.RotatedFiles) != 1 {
		t.Fatalf("RotatedFiles = %v, want 1 file", result.RotatedFiles)
	}

	newKey, err := ctx.Key()
	if err != nil {
		t.Fatalf("Key after rotate: %v", err)
	}
	if string(newKey) == string(oldKey) {
		t.Fatalf("key did not change after RotateKeys")
	}

	encryptedAfter, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if string(encryptedAfter) == string(encryptedBefore) {
		t.Fatalf("ciphertext unchanged after rotation")
	}

	touched, err := ctx.Unlock()
	if err != nil {
		t.Fatalf("Unlock after rotate: %v", err)
	}
	if len(touched) != 1 {
		t.Fatalf("Unlock after rotate touched = %v", touched)
	}
	data, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if string(data) != "password: hunter2\n" {
		t.Fatalf("data did not decrypt correctly after rotation: %q", data)
	}
}

func TestDecryptAfterGitOperationSkipsWithoutFailingWhenKeyMissing(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	// Simulate the key being unavailable (e.g. a fresh clone with no key yet).
	if err := os.Remove(filepath.Join(root, ".repo-enc", "key")); err != nil {
		t.Fatalf("remove key: %v", err)
	}

	if err := ctx.HookPostCheckout(); err != nil {
		t.Fatalf("HookPostCheckout should not fail when key is missing, got: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if strings.Contains(string(data), "hunter2") {
		t.Fatalf("file should remain encrypted without a key")
	}
}
