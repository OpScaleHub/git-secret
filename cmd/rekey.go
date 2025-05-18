package cmd

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/core"
)

// Rekey re-encrypts secrets with the current user set.
func Rekey() error {
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
			return fmt.Errorf("failed to re-encrypt %s: %w", file, err)
		}
	}
	fmt.Println("Rekeyed all secrets with current users.")
	return nil
}
