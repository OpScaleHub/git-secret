package keybackend

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	renccrypto "github.com/OpScaleHub/git-secret/internal/crypto"
)

// FileBackend stores the key as hex text in a file, resolved relative to
// the repo root unless ref is already absolute. This file must never be
// committed: `init` adds it to .gitignore, and `verify` flags it if it
// ever ends up tracked.
type FileBackend struct{}

func (FileBackend) Name() string { return "file" }

func (FileBackend) resolve(repoRoot, ref string) string {
	if filepath.IsAbs(ref) {
		return ref
	}
	return filepath.Join(repoRoot, ref)
}

func (b FileBackend) Get(repoRoot, ref string) ([]byte, error) {
	path := b.resolve(repoRoot, ref)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, path)
		}
		return nil, fmt.Errorf("keybackend(file): read %s: %w", path, err)
	}
	key, err := decodeHexKey(data)
	if err != nil {
		return nil, fmt.Errorf("keybackend(file): %s: %w", path, err)
	}
	return key, nil
}

func (b FileBackend) Generate(repoRoot, ref string) ([]byte, error) {
	path := b.resolve(repoRoot, ref)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("keybackend(file): generate key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("keybackend(file): create key dir: %w", err)
	}
	encoded := []byte(hex.EncodeToString(key) + "\n")
	if err := renccrypto.WriteFileAtomic(path, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("keybackend(file): write %s: %w", path, err)
	}
	return key, nil
}

func decodeHexKey(data []byte) ([]byte, error) {
	trimmed := trimNewline(data)
	key, err := hex.DecodeString(string(trimmed))
	if err != nil {
		return nil, fmt.Errorf("invalid key encoding (expected hex): %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key length %d (expected %d bytes)", len(key), KeySize)
	}
	return key, nil
}

func trimNewline(data []byte) []byte {
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
		data = data[:len(data)-1]
	}
	return data
}
