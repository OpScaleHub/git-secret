package cli

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/OpScaleHub/git-secret/internal/config"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
	"github.com/OpScaleHub/git-secret/internal/keybackend"
)

// InitResult reports what Init actually did, so the caller can print a
// clear, specific summary instead of a generic "done".
type InitResult struct {
	ConfigPath     string
	GeneratedKey   bool
	KeyExportVar   string // set only when the key backend can't persist the key itself (e.g. "env")
	KeyExportHex   string
	HooksInstalled []string
}

// Init bootstraps repo-enc in the current repository: writes a default
// config (idempotent — never overwrites an existing one), ensures a key
// exists, and installs git hooks. patterns seeds the config's `patterns`
// list on first run only.
func Init(patterns []string) (*InitResult, error) {
	root, err := gitutil.RepoRoot()
	if err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		patterns = []string{"secrets/**"}
	}

	cfgPath, err := config.WriteDefault(root, patterns)
	if err != nil {
		return nil, fmt.Errorf("init: write config: %w", err)
	}

	cfg, err := config.Load(root)
	if err != nil {
		return nil, fmt.Errorf("init: load config: %w", err)
	}
	backend, err := keybackend.New(cfg.KeyBackend)
	if err != nil {
		return nil, err
	}

	result := &InitResult{ConfigPath: cfgPath}

	if _, err := backend.Get(root, cfg.KeySource); errors.Is(err, keybackend.ErrKeyNotFound) {
		key, err := backend.Generate(root, cfg.KeySource)
		if err != nil {
			return nil, fmt.Errorf("init: generate key: %w", err)
		}
		result.GeneratedKey = true
		if cfg.KeyBackend == "env" {
			result.KeyExportVar = cfg.KeySource
			result.KeyExportHex = hex.EncodeToString(key)
		}
	} else if err != nil {
		return nil, fmt.Errorf("init: check existing key: %w", err)
	}

	if cfg.KeyBackend == "file" {
		if err := ensureGitignored(root, cfg.KeySource); err != nil {
			return nil, fmt.Errorf("init: update .gitignore: %w", err)
		}
	}

	installed, err := InstallHooks(root)
	if err != nil {
		return nil, fmt.Errorf("init: install hooks: %w", err)
	}
	result.HooksInstalled = installed

	return result, nil
}
