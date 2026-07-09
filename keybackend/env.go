package keybackend

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// EnvBackend reads the key from an environment variable named by ref. It
// never writes to the repo, which suits CI and ephemeral environments.
type EnvBackend struct{}

func (EnvBackend) Name() string { return "env" }

func (EnvBackend) Get(_, ref string) ([]byte, error) {
	val, ok := os.LookupEnv(ref)
	if !ok || val == "" {
		return nil, fmt.Errorf("%w: environment variable %s is not set", ErrKeyNotFound, ref)
	}
	key, err := hex.DecodeString(val)
	if err != nil {
		return nil, fmt.Errorf("keybackend(env): %s: invalid key encoding (expected hex): %w", ref, err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("keybackend(env): %s: invalid key length %d (expected %d bytes)", ref, len(key), KeySize)
	}
	return key, nil
}

// Generate creates new key material but, unlike FileBackend, cannot export
// it into the parent shell's environment from a child process. Callers
// must surface the returned hex string to the user (e.g. "export
// REF=<hex>") and re-run once it's set.
func (EnvBackend) Generate(_, _ string) ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("keybackend(env): generate key: %w", err)
	}
	return key, nil
}
