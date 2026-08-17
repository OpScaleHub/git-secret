package gitutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runGit(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}

// seedRepo creates a real local git repository with one commit on
// "main" and a second branch "other" with a distinguishing file, so
// Clone's --branch handling has something to prove.
func seedRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "git", "init", "-q", "-b", "main")
	runGit(t, dir, "git", "config", "user.email", "test@example.com")
	runGit(t, dir, "git", "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	runGit(t, dir, "git", "add", ".")
	runGit(t, dir, "git", "commit", "-q", "-m", "init")
	runGit(t, dir, "git", "branch", "other")
	runGit(t, dir, "git", "checkout", "-q", "other")
	if err := os.WriteFile(filepath.Join(dir, "on-other-branch"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	runGit(t, dir, "git", "add", ".")
	runGit(t, dir, "git", "commit", "-q", "-m", "other branch")
	runGit(t, dir, "git", "checkout", "-q", "main")
	return dir
}

func TestClone_DefaultBranch(t *testing.T) {
	src := seedRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")
	if err := Clone(CloneOptions{URL: "file://" + src, Dir: dst}); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "README.md")); err != nil {
		t.Fatalf("expected README.md in clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "on-other-branch")); !os.IsNotExist(err) {
		t.Fatalf("expected default branch clone to NOT have on-other-branch, got err=%v", err)
	}
}

func TestClone_SpecificRef(t *testing.T) {
	src := seedRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")
	if err := Clone(CloneOptions{URL: "file://" + src, Dir: dst, Ref: "other"}); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "on-other-branch")); err != nil {
		t.Fatalf("expected on-other-branch in clone of ref 'other': %v", err)
	}
}

func TestClone_IsShallow(t *testing.T) {
	src := seedRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")
	if err := Clone(CloneOptions{URL: "file://" + src, Dir: dst}); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".git", "shallow")); err != nil {
		t.Fatalf("expected a shallow clone (.git/shallow present): %v", err)
	}
}

func TestClone_NonexistentRepo(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "clone")
	err := Clone(CloneOptions{URL: "file:///nonexistent/path/that/does/not/exist", Dir: dst})
	if err == nil {
		t.Fatal("expected an error cloning a nonexistent repository")
	}
}

func TestCloneContext_Cancellation(t *testing.T) {
	src := seedRepo(t)
	dst := filepath.Join(t.TempDir(), "clone")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure the deadline has definitely passed
	err := CloneContext(ctx, CloneOptions{URL: "file://" + src, Dir: dst})
	if err == nil {
		t.Fatal("expected an error from an already-expired context")
	}
}

func TestRepoRootAt(t *testing.T) {
	src := seedRepo(t)
	root, err := RepoRootAt(src)
	if err != nil {
		t.Fatalf("RepoRootAt: %v", err)
	}
	// Resolve symlinks on both sides (e.g. macOS /tmp -> /private/tmp)
	// before comparing.
	wantAbs, _ := filepath.EvalSymlinks(src)
	gotAbs, _ := filepath.EvalSymlinks(root)
	if gotAbs != wantAbs {
		t.Fatalf("RepoRootAt = %q, want %q", gotAbs, wantAbs)
	}
}

func TestRepoRootAt_NotARepo(t *testing.T) {
	dir := t.TempDir()
	if _, err := RepoRootAt(dir); err == nil {
		t.Fatal("expected an error for a directory that isn't a git repo")
	}
}

// sshCommand's paths are process-generated in practice, but it must
// still quote correctly (single quotes escaped) in case a mounted
// Secret's volume path ever contains a character that would otherwise
// break out of the surrounding shell-quoted string.
func TestSSHCommand_QuotesEmbeddedSingleQuote(t *testing.T) {
	got := sshCommand("/tmp/it's-a-key", "/tmp/known_hosts")
	if !strings.Contains(got, `/tmp/it'\''s-a-key`) {
		t.Fatalf("sshCommand did not escape embedded single quote: %s", got)
	}
}

func TestSSHCommand_PinnedKnownHosts(t *testing.T) {
	got := sshCommand("/tmp/key", "/tmp/known_hosts")
	if !strings.Contains(got, "StrictHostKeyChecking=yes") || !strings.Contains(got, "UserKnownHostsFile='/tmp/known_hosts'") {
		t.Fatalf("expected pinned known_hosts to force StrictHostKeyChecking=yes, got: %s", got)
	}
}

func TestSSHCommand_NoPinnedKnownHosts_FallsBackToAcceptNew(t *testing.T) {
	got := sshCommand("/tmp/key", "")
	if !strings.Contains(got, "StrictHostKeyChecking=accept-new") {
		t.Fatalf("expected accept-new fallback without a pinned known_hosts, got: %s", got)
	}
}

func TestSSHCommand_AlwaysIdentitiesOnly(t *testing.T) {
	got := sshCommand("/tmp/key", "")
	if !strings.Contains(got, "IdentitiesOnly=yes") {
		t.Fatalf("expected IdentitiesOnly=yes to always be set, got: %s", got)
	}
}
