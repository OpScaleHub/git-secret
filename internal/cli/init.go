package cli

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/OpScaleHub/git-secret/internal/config"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
	"github.com/OpScaleHub/git-secret/keybackend"
)

// InitOptions configures a bootstrap run. KeyBackend/GPGRecipients only
// take effect on the *first* run in a repo (when .repo-enc.yml doesn't
// exist yet) — WriteConfig/WriteDefault's idempotent refuse-to-overwrite
// behavior means a re-run (e.g. a teammate cloning an already-configured
// repo) always uses the committed config instead, regardless of flags.
type InitOptions struct {
	Patterns      []string
	KeyBackend    string // "" defaults to "file"
	GPGRecipients []string
}

// InitResult reports what Init actually did, so the caller can print a
// clear, specific summary instead of a generic "done".
type InitResult struct {
	ConfigPath   string
	GeneratedKey bool
	// KeyExportVar/Hex are set only when the key backend can't persist
	// the key itself (currently just "env").
	KeyExportVar string
	KeyExportHex string
	// KeyIsCommittable is true for backends (currently just "gpg") whose
	// key file is safe — and expected — to commit, unlike "file"'s raw
	// key, so main.go can print the right guidance either way.
	KeyIsCommittable bool
	KeySource        string
	HooksInstalled   []string
}

// Init bootstraps repo-enc in the current repository: writes a config
// (idempotent — never overwrites an existing one), ensures a key exists,
// and installs git hooks.
func Init(opts InitOptions) (*InitResult, error) {
	root, err := gitutil.RepoRoot()
	if err != nil {
		return nil, err
	}
	patterns := opts.Patterns
	if len(patterns) == 0 {
		patterns = []string{"secrets/**"}
	}

	var cfgPath string
	if opts.KeyBackend == "" || opts.KeyBackend == "file" {
		cfgPath, err = config.WriteDefault(root, patterns)
	} else {
		cfgPath, err = config.WriteConfig(root, &config.Config{
			Version:       config.CurrentVersion,
			Patterns:      patterns,
			KeyBackend:    opts.KeyBackend,
			KeySource:     config.DefaultKeySourceFor(opts.KeyBackend),
			GPGRecipients: opts.GPGRecipients,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("init: write config: %w", err)
	}

	cfg, err := config.Load(root)
	if err != nil {
		return nil, fmt.Errorf("init: load config: %w", err)
	}
	backend, err := resolveBackend(cfg)
	if err != nil {
		return nil, err
	}

	result := &InitResult{ConfigPath: cfgPath, KeySource: cfg.KeySource, KeyIsCommittable: cfg.KeyBackend == "gpg"}

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
