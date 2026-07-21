// Package cli implements the actual behavior behind every subcommand
// (init, status, lock/unlock, encrypt/decrypt, rotate-keys, verify, and
// the hook entrypoints). main.go only parses arguments and calls into
// here, so the logic is testable without spawning a subprocess.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/OpScaleHub/git-secret/internal/config"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
	"github.com/OpScaleHub/git-secret/keybackend"
)

// Context bundles everything a command needs: where the repo is, its
// validated config, and the key backend the config selected.
type Context struct {
	RepoRoot string
	Config   *config.Config
	Backend  keybackend.Backend
}

// Load discovers the repo root and loads+validates its config. Commands
// other than Init require this to succeed.
func Load() (*Context, error) {
	root, err := gitutil.RepoRoot()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, err
	}
	backend, err := resolveBackend(cfg)
	if err != nil {
		return nil, err
	}
	return &Context{RepoRoot: root, Config: cfg, Backend: backend}, nil
}

// resolveBackend looks up cfg.KeyBackend and, for backends that need
// identifiers beyond key_source (currently just "gpg"), wires in the
// config's recipients. This is centralized here — rather than left to
// each call site — so every caller (Load, and Init before a Context
// exists) gets a fully-usable backend, not just the one that happens to
// remember the extra step.
func resolveBackend(cfg *config.Config) (keybackend.Backend, error) {
	b, err := keybackend.New(cfg.KeyBackend)
	if err != nil {
		return nil, err
	}
	if rc, ok := b.(keybackend.RecipientConfigurable); ok {
		b = rc.WithRecipients(cfg.GPGRecipients)
	}
	return b, nil
}

// Key resolves the repo's current symmetric key via the configured backend.
func (c *Context) Key() ([]byte, error) {
	return c.Backend.Get(c.RepoRoot, c.Config.KeySource)
}

// MatchedFiles returns every file git is aware of (tracked or untracked
// but not gitignored) whose repo-relative path matches the config's
// patterns/exclude rules.
func (c *Context) MatchedFiles() ([]string, error) {
	all, err := gitutil.LsFiles(c.RepoRoot)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range all {
		ok, err := c.Config.Matches(f)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, f)
		}
	}
	return out, nil
}

// abs resolves a repo-relative path against RepoRoot, rejecting any path
// that would escape it — via ".." traversal or by being absolute.
// Every path this tool touches (key_source, k8s_secret_paths, and
// explicit `encrypt`/`decrypt` CLI arguments) is documented as repo-
// relative; without this check, a committed key_source like
// "../outside-key", or an `encrypt ../outside.txt` CLI argument, would
// read or write files outside the repository the tool is supposed to be
// scoped to.
func (c *Context) abs(relPath string) (string, error) {
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("path %q must be repo-relative, not absolute", relPath)
	}
	joined := filepath.Join(c.RepoRoot, relPath)
	root := filepath.Clean(c.RepoRoot)
	if joined != root && !strings.HasPrefix(joined, root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the repository root", relPath)
	}
	return joined, nil
}

// rejectSymlink errors out if abs (the resolved path for relPath) is a
// symlink. Every caller that processes a matched path — EncryptPaths,
// DecryptPaths, RotateKeys — must check this before reading it: plain
// os.ReadFile/os.Stat follow symlinks, so a repo-controlled symlink
// committed under a protected pattern (e.g. "secrets/leak.env ->
// ~/.ssh/id_rsa") would otherwise make the tool read an arbitrary local
// file outside the repo and commit its contents as ciphertext the next
// time someone runs `lock`/`rotate-keys`.
func rejectSymlink(relPath, abs string) error {
	fi, err := os.Lstat(abs)
	if err != nil {
		return fmt.Errorf("lstat %s: %w", relPath, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: refusing to follow symlink under a protected path", relPath)
	}
	return nil
}
