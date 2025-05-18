package core

import (
	"os/exec"
	"strings"
)

// Config holds the configuration for the git-secret plugin.
type Config struct {
	Backend    string // "gpg" or "ssh"
	GPGProgram string // Path to gpg executable
	SSHCommand string // Path to ssh executable
	SecretDir  string // Directory to store secret-related files
}

// LoadConfig loads configuration from Git config.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Backend:   "gpg",
		SecretDir: ".gitsecret",
	}

	// Load from git config (local overrides global)
	cfg.Backend = getGitConfig("secret.backend", cfg.Backend)
	cfg.GPGProgram = getGitConfig("secret.gpg_program", "gpg")
	cfg.SSHCommand = getGitConfig("secret.ssh_command", "ssh")
	cfg.SecretDir = getGitConfig("secret.secret_dir", cfg.SecretDir)

	return cfg, nil
}

func getGitConfig(key, fallback string) string {
	out, err := exec.Command("git", "config", "--get", key).Output()
	if err != nil {
		return fallback
	}
	return strings.TrimSpace(string(out))
}
