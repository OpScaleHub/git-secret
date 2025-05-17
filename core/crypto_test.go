package core

import (
	"os"
	"testing"
)

func TestEncryptDecryptFile_GPGMock(t *testing.T) {
	// Setup: create a dummy file
	plain := "test_secret.txt"
	enc := plain + ".secret"
	os.WriteFile(plain, []byte("supersecret"), 0o600)
	defer os.Remove(plain)
	defer os.Remove(enc)

	cfg := &Config{
		Backend:    "gpg",
		GPGProgram: "/bin/true", // mock: does nothing, always succeeds
	}
	userKeys := []string{"FAKEKEYID"}

	err := EncryptFile(plain, cfg, userKeys)
	if err != nil {
		t.Fatalf("EncryptFile (mock) failed: %v", err)
	}
	// Simulate encrypted file creation
	os.WriteFile(enc, []byte("encrypted"), 0o600)

	err = DecryptFile(enc, plain, cfg)
	if err != nil {
		t.Fatalf("DecryptFile (mock) failed: %v", err)
	}
}
