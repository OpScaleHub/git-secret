package main

import (
	"os/exec"
	"strings"
)

// gitProvenance returns the current commit SHA and origin URL if the
// working directory is inside a git repo, or empty strings otherwise.
// Best-effort: git missing, not a repo, or no origin all just yield "".
func gitProvenance() (revision, repo string) {
	revision = gitOutput("rev-parse", "HEAD")
	// A dirty tree means the sealed plaintext may not match the commit --
	// flag it so the annotation isn't quietly misleading. Only changes to
	// tracked files count: an untracked file can't be what was sealed from
	// the commit, and the usual "keyfold seal ... > new.yaml" creates one
	// (the redirect target) before this even runs.
	if revision != "" && gitOutput("status", "--porcelain", "--untracked-files=no") != "" {
		revision += "-dirty"
	}
	repo = gitOutput("config", "--get", "remote.origin.url")
	return revision, repo
}

func gitOutput(args ...string) string {
	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
