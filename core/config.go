package core

// Config holds the configuration for the git-secret plugin.
type Config struct {
	Backend    string // "gpg" or "ssh"
	GPGProgram string // Path to gpg executable
	SSHCommand string // Path to ssh executable
	SecretDir  string // Directory to store secret-related files
}

// LoadConfig loads configuration from Git config.
func LoadConfig() (*Config, error) {
	// TODO: Implement loading configuration from .git/config and global ~/.gitconfig
	return &Config{Backend: "gpg", SecretDir: ".gitsecret"}, nil // Default placeholder
}
