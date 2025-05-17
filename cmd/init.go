package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/OpScaleHub/git-secret/core"
)

// Init initializes the secret management system.
func Init() error {
	// Load configuration (get secret dir)
	config, err := core.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create secret directory
	if err := core.CreateSecretDir(config.SecretDir); err != nil {
		return fmt.Errorf("failed to create secret dir: %w", err)
	}

	// Create users file if not exists
	usersFile := filepath.Join(config.SecretDir, "users")
	if _, err := os.Stat(usersFile); os.IsNotExist(err) {
		f, err := os.Create(usersFile)
		if err != nil {
			return fmt.Errorf("failed to create users file: %w", err)
		}
		defer f.Close()
	}

	// Create tracked files list if not exists
	trackedFile := filepath.Join(config.SecretDir, "tracked")
	if _, err := os.Stat(trackedFile); os.IsNotExist(err) {
		f, err := os.Create(trackedFile)
		if err != nil {
			return fmt.Errorf("failed to create tracked file: %w", err)
		}
		defer f.Close()
	}

	// Update .gitignore
	if err := core.UpdateGitIgnore(config.SecretDir); err != nil {
		return fmt.Errorf("failed to update .gitignore: %w", err)
	}

	fmt.Println("git-secret initialized successfully.")
	return nil
}
