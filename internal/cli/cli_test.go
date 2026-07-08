package cli

import (
	"os"
	"os/exec"
	"path/filepath"
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

	runGit(t, root, "commit", "-q", "-m", "add secret")
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
	if len(problems) != 1 || problems[0] != "secrets/db.yaml" {
		t.Fatalf("Verify problems = %v, want [secrets/db.yaml]", problems)
	}

	if err := ctx.HookPrePush(); err == nil {
		t.Fatalf("expected HookPrePush to block push on leaked plaintext")
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
