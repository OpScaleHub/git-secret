package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGitProvenance_UntrackedFilesAreNotDirty: sealing into the repo
// (keyfold seal ... > new.yaml) creates an untracked file before the
// provenance check runs; that must not mark the revision -dirty. A changed
// tracked file still must.
func TestGitProvenance_UntrackedFilesAreNotDirty(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.email=t@e", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git("init", "-q")
	os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("a\n"), 0o644)
	git("add", ".")
	git("commit", "-q", "-m", "init")
	t.Chdir(repo)

	os.WriteFile(filepath.Join(repo, "gitsecret.yaml"), []byte("x\n"), 0o644) // untracked
	if rev, _ := gitProvenance(); rev == "" || strings.HasSuffix(rev, "-dirty") {
		t.Fatalf("untracked file made the revision %q", rev)
	}
	os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("b\n"), 0o644)
	if rev, _ := gitProvenance(); !strings.HasSuffix(rev, "-dirty") {
		t.Fatalf("modified tracked file not flagged: %q", rev)
	}
}
