package cmd

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/core"
)

// Decrypt decrypts all tracked files.
func Decrypt() error {
	config, err := core.LoadConfig()
	if err != nil {
		return err
	}
	files, err := core.ListTrackedFiles(config)
	if err != nil {
		return err
	}
	for _, file := range files {
		encFile := file + ".secret"
		if err := core.DecryptFile(encFile, file, config); err != nil {
			return fmt.Errorf("failed to decrypt %s: %w", encFile, err)
		}
	}
	fmt.Println("Decrypted all tracked files.")
	return nil
}
