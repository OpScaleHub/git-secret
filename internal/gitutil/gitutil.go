// Package gitutil wraps the small set of `git` subcommands the CLI needs
// to stage encrypted blobs, inspect committed content, and locate hooks —
// without touching the working tree file that the user actually sees.
package gitutil

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// RepoRoot returns the absolute path to the working tree root of the
// repository containing the current directory.
func RepoRoot() (string, error) {
	out, err := run(nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("gitutil: not inside a git repository: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// HooksDir returns the directory git will look in for hooks, honoring
// core.hooksPath if the repo has it configured.
func HooksDir(repoRoot string) (string, error) {
	out, err := run(&repoRoot, "rev-parse", "--git-path", "hooks")
	if err != nil {
		return "", fmt.Errorf("gitutil: resolve hooks dir: %w", err)
	}
	dir := strings.TrimSpace(out)
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(repoRoot, dir)
	}
	return dir, nil
}

// LsFiles lists every file git would track: already-committed files plus
// untracked files that aren't gitignored. Pattern matching is applied by
// the caller against this list.
//
// Uses -z (NUL-delimited output): without it, git C-quotes "unusual"
// filenames (e.g. ones containing a literal newline) rather than
// emitting the raw path, and a plain newline-split would both mis-parse
// the quoting and be corrupted by the embedded newline itself — letting
// a maliciously-named protected file slip past pattern matching
// entirely. See splitNUL.
func LsFiles(repoRoot string) ([]string, error) {
	out, err := run(&repoRoot, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, fmt.Errorf("gitutil: ls-files: %w", err)
	}
	return splitNUL(out), nil
}

// LsTree lists every path in the tree committed at rev, NUL-delimited
// for the same reason LsFiles is (see its doc). Unlike LsFiles (which
// reflects the working tree/index), this reflects exactly what's
// committed at rev, so it's what revision-pinned verification uses.
func LsTree(repoRoot, rev string) ([]string, error) {
	out, err := run(&repoRoot, "ls-tree", "-r", "--name-only", "-z", rev)
	if err != nil {
		return nil, fmt.Errorf("gitutil: ls-tree %s: %w", rev, err)
	}
	return splitNUL(out), nil
}

// StagedFiles lists paths staged for the next commit (added/copied/modified),
// which is what the pre-commit hook needs to inspect. See LsFiles' doc
// for why -z/splitNUL, not a plain newline split.
func StagedFiles(repoRoot string) ([]string, error) {
	out, err := run(&repoRoot, "diff", "-z", "--cached", "--name-only", "--diff-filter=ACMR")
	if err != nil {
		return nil, fmt.Errorf("gitutil: diff --cached: %w", err)
	}
	return splitNUL(out), nil
}

// ChangedPaths returns the paths that rev adds, modifies, copies, or
// renames relative to its parent(s) — or, for a root commit, relative to
// the empty tree (via --root). -m makes a merge commit report the union
// of per-parent diffs instead of the default empty combined-diff, so a
// secret reintroduced only by a merge's conflict resolution isn't missed.
func ChangedPaths(repoRoot, rev string) ([]string, error) {
	out, err := run(&repoRoot, "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "-m", "-z", "--diff-filter=ACMR", rev)
	if err != nil {
		return nil, fmt.Errorf("gitutil: diff-tree %s: %w", rev, err)
	}
	return splitNUL(out), nil
}

// ZeroOID is the all-zeroes object id git uses in hook protocols (e.g.
// pre-push ref-update lines) to mean "this ref doesn't exist" — a new
// ref being created, or an old ref being deleted.
const ZeroOID = "0000000000000000000000000000000000000000"

// IsZeroOID reports whether s is git's all-zeroes placeholder OID.
func IsZeroOID(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if r != '0' {
			return false
		}
	}
	return true
}

// RevList returns the SHAs of every commit in oldRev..newRev, oldest
// ancestry last (git's default rev-list order). If oldRev is the
// all-zero OID (a brand new ref, per the pre-push hook protocol), it
// instead returns every commit reachable from newRev — mirroring git's
// own sample pre-push hook, which examines the ref's entire history in
// that case since there's no prior remote state to diff against.
func RevList(repoRoot, oldRev, newRev string) ([]string, error) {
	var args []string
	if IsZeroOID(oldRev) {
		args = []string{"rev-list", newRev}
	} else {
		args = []string{"rev-list", oldRev + ".." + newRev}
	}
	out, err := run(&repoRoot, args...)
	if err != nil {
		return nil, fmt.Errorf("gitutil: rev-list: %w", err)
	}
	return splitLines(out), nil
}

// ReadStaged returns the content of path as it currently sits in the
// index (i.e. what would be committed), regardless of working tree state.
func ReadStaged(repoRoot, path string) ([]byte, error) {
	out, err := runBytes(&repoRoot, "show", ":"+path)
	if err != nil {
		return nil, fmt.Errorf("gitutil: read staged %s: %w", path, err)
	}
	return out, nil
}

// ReadAtRev returns the content of path as committed at rev (e.g. "HEAD").
// Returns ErrNotFound-compatible error text when the path doesn't exist at
// that revision; callers check with IsMissingPath.
func ReadAtRev(repoRoot, rev, path string) ([]byte, error) {
	out, err := runBytes(&repoRoot, "show", rev+":"+path)
	if err != nil {
		return nil, fmt.Errorf("gitutil: read %s at %s: %w", path, rev, err)
	}
	return out, nil
}

// HashObjectWrite writes data into the object database as a blob and
// returns its SHA, without touching the working tree or index.
func HashObjectWrite(repoRoot string, data []byte) (string, error) {
	out, err := runStdin(&repoRoot, data, "hash-object", "-w", "--stdin")
	if err != nil {
		return "", fmt.Errorf("gitutil: hash-object: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// UpdateIndexBlob points the index entry for path at an existing blob sha
// (mode "100644"), replacing whatever content was staged. This is how the
// pre-commit hook swaps in ciphertext for a commit while leaving the
// working tree file exactly as the user has it.
func UpdateIndexBlob(repoRoot, sha, path string) error {
	arg := fmt.Sprintf("100644,%s,%s", sha, path)
	if _, err := run(&repoRoot, "update-index", "--add", "--cacheinfo", arg); err != nil {
		return fmt.Errorf("gitutil: update-index %s: %w", path, err)
	}
	return nil
}

// SetSkipWorktree sets or clears the skip-worktree bit on path, telling
// git to stop reporting/diffing local content differences for it. Used
// so a decrypted-for-viewing file doesn't show as "modified" in `git
// status` merely because plaintext-on-disk differs from ciphertext-in-
// the-index by design. Note: `git update-index --cacheinfo` (used by
// UpdateIndexBlob) silently clears this bit as a side effect of
// replacing the index entry — callers that re-point an index entry at a
// new blob must re-apply skip-worktree afterward if they want it kept.
func SetSkipWorktree(repoRoot, path string, skip bool) error {
	flag := "--no-skip-worktree"
	if skip {
		flag = "--skip-worktree"
	}
	if _, err := run(&repoRoot, "update-index", flag, path); err != nil {
		return fmt.Errorf("gitutil: update-index %s %s: %w", flag, path, err)
	}
	return nil
}

// IsSkipWorktree reports whether path currently has the skip-worktree
// bit set.
func IsSkipWorktree(repoRoot, path string) (bool, error) {
	out, err := run(&repoRoot, "ls-files", "-v", "--", path)
	if err != nil {
		return false, fmt.Errorf("gitutil: ls-files -v %s: %w", path, err)
	}
	return strings.HasPrefix(out, "S "), nil
}

func run(dir *string, args ...string) (string, error) {
	b, err := runBytes(dir, args...)
	return string(b), err
}

func runStdin(dir *string, stdin []byte, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != nil {
		cmd.Dir = *dir
	}
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func runBytes(dir *string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	if dir != nil {
		cmd.Dir = *dir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// IsMissingPath reports whether err from ReadAtRev/ReadStaged means the
// path simply doesn't exist at that revision (e.g. not committed yet),
// as opposed to a real I/O or git failure.
func IsMissingPath(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{
		"does not exist in",
		"exists on disk, but not in",
		"bad revision",
		"unknown revision",
		"invalid object name",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// splitNUL parses -z (NUL-delimited) git output, which — unlike the
// default newline-delimited form — never quotes/escapes unusual
// filenames, so every entry is the literal repo-relative path with no
// further unescaping needed.
func splitNUL(s string) []string {
	s = strings.TrimRight(s, "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}
