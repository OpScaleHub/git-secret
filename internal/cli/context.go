// Package cli implements the actual behavior behind every subcommand
// (init, status, lock/unlock, encrypt/decrypt, rotate-keys, verify, and
// the hook entrypoints). main.go only parses arguments and calls into
// here, so the logic is testable without spawning a subprocess.
package cli

import (
	"path/filepath"

	"github.com/OpScaleHub/git-secret/internal/config"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
	"github.com/OpScaleHub/git-secret/internal/keybackend"
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
	backend, err := keybackend.New(cfg.KeyBackend)
	if err != nil {
		return nil, err
	}
	return &Context{RepoRoot: root, Config: cfg, Backend: backend}, nil
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

// abs resolves a repo-relative path against RepoRoot.
func (c *Context) abs(relPath string) string {
	return filepath.Join(c.RepoRoot, relPath)
}
