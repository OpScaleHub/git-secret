package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/gitutil"
)

func TestUnlockHidesFileFromGitStatus(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "-m", "add secret") // hook-processed: commits ciphertext

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	hidden, err := gitutil.IsSkipWorktree(root, "secrets/db.yaml")
	if err != nil {
		t.Fatalf("IsSkipWorktree: %v", err)
	}
	if !hidden {
		t.Fatalf("expected skip-worktree to be set after Unlock")
	}

	out := runGit(t, root, "status", "--short")
	if strings.Contains(out, "secrets/db.yaml") {
		t.Fatalf("secrets/db.yaml should not appear in git status after Unlock, got: %q", out)
	}

	states, err := ctx.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(states) != 1 || !states[0].Hidden {
		t.Fatalf("Status() Hidden = %+v, want Hidden=true", states)
	}
}

func TestLockClearsSkipWorktree(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "-m", "add secret")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := ctx.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	hidden, err := gitutil.IsSkipWorktree(root, "secrets/db.yaml")
	if err != nil {
		t.Fatalf("IsSkipWorktree: %v", err)
	}
	if hidden {
		t.Fatalf("expected skip-worktree to be cleared after Lock")
	}
}

// TestEditAfterUnlockRequiresLockBeforeGitAdd documents a real, sharp git
// behavior discovered while building this feature: skip-worktree isn't
// merely cosmetic — it makes `git add`/`commit -a`/`commit <path>` all
// treat the path as if it has no local changes at all. A plain `git add`
// on a skip-worktree'd file fails loudly with a sparse-checkout-flavored
// error in modern git (2.53), even though this repo never touched sparse
// checkout. `git secret lock` sidesteps this entirely: it re-encrypts
// straight from the current working-tree content (not through `git add`)
// and clears skip-worktree itself, so the resulting `git add` — of
// already-identical ciphertext — works normally. The supported edit
// workflow is therefore: unlock, edit, lock, then add/commit as usual.
func TestEditAfterUnlockRequiresLockBeforeGitAdd(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "-m", "add secret")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter3\n")

	// A plain `git add` while skip-worktree is set must fail (loudly,
	// safely -- nothing gets silently dropped or silently committed).
	cmd := exec.Command("git", "add", "secrets/db.yaml")
	cmd.Dir = root
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected plain `git add` to fail while skip-worktree is set (this pins a real git behavior; if this now passes, git's behavior changed and the documented workaround may be obsolete)")
	}

	// The supported path: lock re-encrypts the edit and clears
	// skip-worktree, so `git add` + `git commit` work normally after.
	if _, err := ctx.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "-m", "rotate password")

	problems, err := ctx.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("Verify found problems: %v", problems)
	}

	touched, err := ctx.Unlock()
	if err != nil {
		t.Fatalf("Unlock (final check): %v", err)
	}
	if len(touched) != 1 {
		t.Fatalf("Unlock touched = %v", touched)
	}
	data, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if string(data) != "password: hunter3\n" {
		t.Fatalf("committed content incorrect: %q", data)
	}
}

// TestHookPreCommitReappliesSkipWorktree is the precise regression test
// for the sharpest edge found while building this: `git update-index
// --cacheinfo` (used internally by HookPreCommit to swap in ciphertext)
// silently clears any skip-worktree bit as a side effect of replacing
// the index entry. Reproducing this needs staged plaintext content on a
// skip-worktree'd path -- unreachable through plain `git add` (modern
// git refuses that combination outright, see
// TestEditAfterUnlockRequiresLockBeforeGitAdd), but reachable through
// lower-level index manipulation (e.g. a merge, or direct `git
// update-index <path>`), which is what this test simulates directly.
func TestHookPreCommitReappliesSkipWorktree(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "-m", "add secret")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter3\n")

	// Stage the new plaintext directly, bypassing the `git add` porcelain
	// gate that blocks skip-worktree'd paths (see gitutil.SetSkipWorktree's
	// doc comment for why `--cacheinfo`/plain `update-index` differs).
	cmd := exec.Command("git", "update-index", "secrets/db.yaml")
	cmd.Dir = root
	if err := cmd.Run(); err != nil {
		t.Fatalf("git update-index secrets/db.yaml: %v", err)
	}

	if err := ctx.HookPreCommit(); err != nil {
		t.Fatalf("HookPreCommit: %v", err)
	}

	hidden, err := gitutil.IsSkipWorktree(root, "secrets/db.yaml")
	if err != nil {
		t.Fatalf("IsSkipWorktree: %v", err)
	}
	if !hidden {
		t.Fatalf("HookPreCommit must re-apply skip-worktree after update-index --cacheinfo clears it")
	}

	staged, err := gitutil.ReadStaged(root, "secrets/db.yaml")
	if err != nil {
		t.Fatalf("ReadStaged: %v", err)
	}
	if strings.Contains(string(staged), "hunter3") {
		t.Fatalf("staged content should be encrypted, got: %q", staged)
	}
}

// TestSkipWorktreeSurvivesUnrelatedCommit confirms skip-worktree is
// scoped per-path: committing a change to a *different* matched file
// must not clear it on paths that were never staged in that commit.
func TestSkipWorktreeSurvivesUnrelatedCommit(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	writeRepoFile(t, root, "secrets/other.yaml", "other: value\n")
	runGit(t, root, "add", "secrets/db.yaml", "secrets/other.yaml")
	runGit(t, root, "commit", "-q", "-m", "add secrets")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Re-lock and commit a change to a *different* matched file.
	writeRepoFile(t, root, "secrets/other.yaml", "other: newvalue\n")
	if _, err := ctx.EncryptPaths([]string{"secrets/other.yaml"}); err != nil {
		t.Fatalf("EncryptPaths: %v", err)
	}
	runGit(t, root, "add", "secrets/other.yaml")
	runGit(t, root, "commit", "-q", "-m", "update other secret")

	hidden, err := gitutil.IsSkipWorktree(root, "secrets/db.yaml")
	if err != nil {
		t.Fatalf("IsSkipWorktree: %v", err)
	}
	if !hidden {
		t.Fatalf("db.yaml's skip-worktree bit should be untouched by a commit that never staged it")
	}

	out := runGit(t, root, "status", "--short")
	if strings.Contains(out, "secrets/db.yaml") {
		t.Fatalf("secrets/db.yaml should not appear in git status, got: %q", out)
	}
}

func TestHookPostCheckoutSetsSkipWorktreeOnFreshDecrypt(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "-m", "add secret")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Simulate a fresh clone: the file is committed ciphertext with no
	// skip-worktree state at all yet (HookPostCheckout's normal path).
	if _, err := ctx.EncryptPaths([]string{"secrets/db.yaml"}); err != nil {
		t.Fatalf("EncryptPaths: %v", err)
	}
	if err := ctx.HookPostCheckout(); err != nil {
		t.Fatalf("HookPostCheckout: %v", err)
	}

	hidden, err := gitutil.IsSkipWorktree(root, "secrets/db.yaml")
	if err != nil {
		t.Fatalf("IsSkipWorktree: %v", err)
	}
	if !hidden {
		t.Fatalf("expected post-checkout's automatic decrypt to also hide the file from git status")
	}
}

func TestEncryptExplicitPathsClearsSkipWorktree(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "-m", "add secret")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.DecryptPaths([]string{"secrets/db.yaml"}); err != nil {
		t.Fatalf("DecryptPaths: %v", err)
	}
	if _, err := ctx.EncryptPaths([]string{"secrets/db.yaml"}); err != nil {
		t.Fatalf("EncryptPaths: %v", err)
	}

	hidden, err := gitutil.IsSkipWorktree(root, "secrets/db.yaml")
	if err != nil {
		t.Fatalf("IsSkipWorktree: %v", err)
	}
	if hidden {
		t.Fatalf("explicit `encrypt` should clear skip-worktree just like Lock")
	}
}

func TestRotateKeysClearsSkipWorktree(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")
	runGit(t, root, "add", "secrets/db.yaml")
	runGit(t, root, "commit", "-q", "-m", "add secret")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := ctx.RotateKeys(); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}

	hidden, err := gitutil.IsSkipWorktree(root, "secrets/db.yaml")
	if err != nil {
		t.Fatalf("IsSkipWorktree: %v", err)
	}
	if hidden {
		t.Fatalf("rotate-keys writes ciphertext to the working tree, so skip-worktree should be cleared")
	}

	data, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if strings.Contains(string(data), "hunter2") {
		t.Fatalf("working tree should hold ciphertext after rotate-keys, got: %q", data)
	}
}
