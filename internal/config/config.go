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
	// GPGRecipients are GPG fingerprints the key is wrapped to when
	// KeyBackend is "gpg". Not secret — these are public key
	// identifiers — so this is committed as part of the repo config,
	// same as Patterns/Exclude.
	GPGRecipients []string `yaml:"gpg_recipients,omitempty"`
}

// validBackends are the key_backend values recognized by this build.
// "kms" is reserved for a future backend behind the same
// keybackend.Backend interface; selecting it today is a validation
// error rather than a silent no-op.
var validBackends = map[string]bool{
	"file": true,
	"env":  true,
	"gpg":  true,
}

// DefaultKeySourceFor returns the default key_source for a given
// key_backend. "gpg" gets a distinct default from "file" (".repo-enc/key.gpg"
// vs ".repo-enc/key") since the two are semantically different — one
// gitignored/secret, one meant to be committed — and switching backends
// shouldn't silently collide with a stale key from the other.
func DefaultKeySourceFor(backend string) string {
	if backend == "gpg" {
		return ".repo-enc/key.gpg"
	}
	return ".repo-enc/key"
}

func defaults() *Config {
	return &Config{
		Version:    CurrentVersion,
		KeyBackend: "file",
		KeySource:  DefaultKeySourceFor("file"),
	}
}

// GlobalConfigDirEnvVar overrides where GlobalPath looks, bypassing OS
// convention detection entirely. Useful for reproducible CI/container
// setups and for tests, which otherwise can't isolate the global config
// path portably (os.UserConfigDir ignores XDG_CONFIG_HOME on macOS by
// design, unlike on Linux).
const GlobalConfigDirEnvVar = "REPO_ENC_CONFIG_DIR"

// GlobalPath returns the path to the user's global override config,
// respecting OS conventions (XDG on Linux, Application Support on macOS,
// AppData on Windows) via os.UserConfigDir, unless GlobalConfigDirEnvVar
// is set.
func GlobalPath() (string, error) {
	if dir := os.Getenv(GlobalConfigDirEnvVar); dir != "" {
		return filepath.Join(dir, "config.yml"), nil
	}
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
// (patterns, exclude, gpg_recipients) are the union of global and
// repo-local entries, so a user's personal defaults (e.g. "*.secret.*"
// patterns, or always including their own key as a gpg recipient) apply
// everywhere without needing to be copy-pasted into every repo.
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
	base.GPGRecipients = unionDedup(base.GPGRecipients, overlay.GPGRecipients)
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
	if c.KeyBackend == "gpg" && len(c.GPGRecipients) == 0 {
		return fmt.Errorf("config: key_backend \"gpg\" requires at least one entry in gpg_recipients")
	}
	for _, p := range append(append([]string{}, c.Patterns...), c.Exclude...) {
		if _, err := filepath.Match(lastSegment(p), "x"); err != nil {
			return fmt.Errorf("config: invalid glob pattern %q: %w", p, err)
		}
	}
	return nil
}

const configHeader = "# repo-enc config: https://github.com/OpScaleHub/git-secret\n" +
	"# 'patterns' are glob paths (relative to repo root, '**' matches any depth)\n" +
	"# that get transparently encrypted by the installed git hooks.\n"

// WriteDefault writes a starter config to repoRoot/.repo-enc.yml. It
// refuses to overwrite an existing file so `init` stays idempotent.
func WriteDefault(repoRoot string, patterns []string) (string, error) {
	cfg := defaults()
	cfg.Patterns = patterns
	return WriteConfig(repoRoot, cfg)
}

// WriteConfig writes cfg as the starter .repo-enc.yml, refusing to
// overwrite an existing file (same idempotency contract as WriteDefault).
// Used by `init` when the caller has chosen a non-default key backend
// (e.g. gpg) and needs to set key_backend/key_source/gpg_recipients
// before the file is ever written.
func WriteConfig(repoRoot string, cfg *Config) (string, error) {
	path := filepath.Join(repoRoot, FileName)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return path, writeConfigFile(path, cfg)
}

// Save overwrites repoRoot/.repo-enc.yml with cfg unconditionally, unlike
// WriteDefault/WriteConfig's refuse-if-exists guard. Used by adduser/
// removeuser, which are legitimate in-place edits to an already-existing,
// already-customized config rather than a first-time bootstrap.
func Save(repoRoot string, cfg *Config) error {
	path := filepath.Join(repoRoot, FileName)
	return writeConfigFile(path, cfg)
}

func writeConfigFile(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: marshal config: %w", err)
	}
	if err := os.WriteFile(path, []byte(configHeader+string(data)), 0o644); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
}
