package core

import (
	"fmt"
	"os/exec"
)

// EncryptFile encrypts a single file using the configured backend.
func EncryptFile(filePath string, config *Config, userKeys []string) error {
	if config.Backend == "gpg" {
		for _, key := range userKeys {
			outFile := filePath + ".secret"
			cmd := exec.Command(config.GPGProgram, "--yes", "--batch", "--output", outFile, "--encrypt", "--recipient", key, filePath)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("gpg encryption failed for %s: %w", filePath, err)
			}
		}
		return nil
	}
	// SSH backend: not implemented
	return fmt.Errorf("encryption backend '%s' not implemented", config.Backend)
}

// DecryptFile decrypts a single file using the configured backend.
func DecryptFile(encryptedFilePath string, outputFilePath string, config *Config) error {
	if config.Backend == "gpg" {
		cmd := exec.Command(config.GPGProgram, "--yes", "--batch", "--output", outputFilePath, "--decrypt", encryptedFilePath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("gpg decryption failed for %s: %w", encryptedFilePath, err)
		}
		return nil
	}
	// SSH backend: not implemented
	return fmt.Errorf("decryption backend '%s' not implemented", config.Backend)
}
