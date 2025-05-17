package cmd

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/core"
)

// Encrypt encrypts all tracked files.
func Encrypt() error {
	config, err := core.LoadConfig()
	if err != nil {
		return err
	}
	userKeys, err := core.ListUserKeys(config)
	if err != nil {
		return err
	}
	files, err := core.ListTrackedFiles(config)
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := core.EncryptFile(file, config, userKeys); err != nil {
			return fmt.Errorf("failed to encrypt %s: %w", file, err)
		}
	}
	fmt.Println("Encrypted all tracked files.")
	return nil
}
