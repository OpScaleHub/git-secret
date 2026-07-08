// Package config loads and validates the repo-local .repo-enc.yml, merged
// with an optional global override file for machine-local defaults (e.g.
// which key backend to use).
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// FileName is the repo-local config file, committed to the repo.
const FileName = ".repo-enc.yml"

// CurrentVersion is the only config schema version this build understands.
const CurrentVersion = 1

// Config is the merged, validated configuration for a repository.
type Config struct {
	Version    int      `yaml:"version"`
	Patterns   []string `yaml:"patterns"`
	Exclude    []string `yaml:"exclude,omitempty"`
	KeyBackend string   `yaml:"key_backend"`
	KeySource  string   `yaml:"key_source"`
}

// validBackends are the key_backend values recognized by this build.
// "gpg" and "kms" are reserved for future backends behind the same
// keybackend.KeyBackend interface; selecting them today is a validation
// error rather than a silent no-op.
var validBackends = map[string]bool{
	"file": true,
	"env":  true,
}

func defaults() *Config {
	return &Config{
		Version:    CurrentVersion,
		KeyBackend: "file",
		KeySource:  ".repo-enc/key",
	}
}

// GlobalPath returns the path to the user's global override config,
// respecting OS conventions (XDG on Linux, Application Support on macOS,
// AppData on Windows) via os.UserConfigDir.
func GlobalPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "repo-enc", "config.yml"), nil
}

// Load reads the repo-local config at repoRoot/.repo-enc.yml, merges in
// the global override file if present, and validates the result.
//
// Merge semantics: scalar fields (key_backend, key_source) are repo-local
// if set there, else global, else built-in default. List fields
// (patterns, exclude) are the union of global and repo-local entries, so a
// user's personal default patterns (e.g. "*.secret.*") apply everywhere
// without needing to be copy-pasted into every repo.
func Load(repoRoot string) (*Config, error) {
	cfg := defaults()

	if globalPath, err := GlobalPath(); err == nil {
		if global, err := loadFile(globalPath); err == nil {
			mergeInto(cfg, global)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("config: read global config: %w", err)
		}
	}

	repoPath := filepath.Join(repoRoot, FileName)
	repo, err := loadFile(repoPath)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", repoPath, err)
	}
	mergeInto(cfg, repo)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// mergeInto layers overlay onto base in place, following Load's documented
// precedence rules.
func mergeInto(base, overlay *Config) {
	if overlay.Version != 0 {
		base.Version = overlay.Version
	}
	if overlay.KeyBackend != "" {
		base.KeyBackend = overlay.KeyBackend
	}
	if overlay.KeySource != "" {
		base.KeySource = overlay.KeySource
	}
	base.Patterns = unionDedup(base.Patterns, overlay.Patterns)
	base.Exclude = unionDedup(base.Exclude, overlay.Exclude)
}

func unionDedup(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Validate checks that the config is well-formed and usable.
func (c *Config) Validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("config: unsupported version %d (expected %d)", c.Version, CurrentVersion)
	}
	if len(c.Patterns) == 0 {
		return fmt.Errorf("config: at least one entry in 'patterns' is required")
	}
	if !validBackends[c.KeyBackend] {
		return fmt.Errorf("config: unknown key_backend %q", c.KeyBackend)
	}
	if c.KeySource == "" {
		return fmt.Errorf("config: key_source must not be empty")
	}
	for _, p := range append(append([]string{}, c.Patterns...), c.Exclude...) {
		if _, err := filepath.Match(lastSegment(p), "x"); err != nil {
			return fmt.Errorf("config: invalid glob pattern %q: %w", p, err)
		}
	}
	return nil
}

// WriteDefault writes a starter config to repoRoot/.repo-enc.yml. It
// refuses to overwrite an existing file so `init` stays idempotent.
func WriteDefault(repoRoot string, patterns []string) (string, error) {
	path := filepath.Join(repoRoot, FileName)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	cfg := defaults()
	cfg.Patterns = patterns
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("config: marshal default config: %w", err)
	}
	header := "# repo-enc config: https://github.com/OpScaleHub/git-secret\n" +
		"# 'patterns' are glob paths (relative to repo root, '**' matches any depth)\n" +
		"# that get transparently encrypted by the installed git hooks.\n"
	if err := os.WriteFile(path, []byte(header+string(data)), 0o644); err != nil {
		return "", fmt.Errorf("config: write %s: %w", path, err)
	}
	return path, nil
}
