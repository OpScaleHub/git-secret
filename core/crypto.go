package core

import "fmt"

// EncryptFile encrypts a single file using the configured backend.
func EncryptFile(filePath string, config *Config, userKeys []string) error {
	fmt.Printf("Encrypting file: %s using backend: %s\n", filePath, config.Backend)
	// TODO: Implement encryption logic based on config.Backend (gpg or ssh)
	// For GPG: execute `gpg --encrypt --recipient <keyID> ...`
	// For SSH: use openssl or golang.org/x/crypto/ssh
	return nil
}

// DecryptFile decrypts a single file using the configured backend.
func DecryptFile(encryptedFilePath string, outputFilePath string, config *Config) error {
	fmt.Printf("Decrypting file: %s to %s using backend: %s\n", encryptedFilePath, outputFilePath, config.Backend)
	// TODO: Implement decryption logic based on config.Backend
	// For GPG: execute `gpg --decrypt ...`
	// For SSH: use openssl or golang.org/x/crypto/ssh
	// Note: For SSH, you'll need the user's private key, which this plugin
	// assumes is managed by the user (e.g., via ssh-agent).
	return nil
}
