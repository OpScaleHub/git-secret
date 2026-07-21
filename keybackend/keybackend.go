// Package keybackend resolves the symmetric key used to encrypt/decrypt a
// repository's tracked files. Backends are pluggable so new sources (GPG,
// cloud KMS) can be added later without touching the CLI or crypto layers.
package keybackend

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// KeySize is the key length every backend must produce. Both ciphers in
// the crypto package use 32-byte keys, so backends don't need to know which
// cipher is active.
const KeySize = 32

// ErrKeyNotFound is returned by Get when ref does not resolve to existing
// key material. Callers use this to distinguish "not configured yet" from
// other I/O errors (e.g. to choose exit code 2, per the CLI's documented
// codes).
var ErrKeyNotFound = errors.New("keybackend: key not found")

// Backend resolves and (where possible) generates key material referenced
// by a config's key_source string. The meaning of ref is backend-specific:
// a filesystem path for "file", an environment variable name for "env".
type Backend interface {
	// Name identifies the backend, matching the config's key_backend value.
	Name() string
	// Get returns the existing key referenced by ref, or ErrKeyNotFound if
	// it hasn't been created yet. repoRoot is used by backends whose ref
	// is a repo-relative path.
	Get(repoRoot, ref string) ([]byte, error)
	// Generate creates fresh key material and, when the backend supports
	// it, persists it at ref. It always produces a new key; callers that
	// want "create only if missing" semantics should call Get first.
	Generate(repoRoot, ref string) ([]byte, error)
}

// RecipientConfigurable is implemented by backends whose Generate needs
// identifiers beyond ref — currently just GPGBackend, whose Generate
// must know who the key is wrapped for. Callers that resolve a Backend
// from config type-assert for this interface and call WithRecipients
// before using it. FileBackend/EnvBackend do not implement it: growing
// Backend.Get/Generate itself to carry a recipients parameter would
// force every backend (including future ones) to accept a parameter
// that's meaningless to most of them.
type RecipientConfigurable interface {
	WithRecipients(recipients []string) Backend
}

// registry maps a config's key_backend name to its implementation.
var registry = map[string]Backend{
	FileBackend{}.Name(): FileBackend{},
	EnvBackend{}.Name():  EnvBackend{},
	GPGBackend{}.Name():  GPGBackend{},
}

// resolveConfined resolves ref against repoRoot for backends whose key
// material is a filesystem path ("file", "gpg"). key_source is
// documented as repo-relative, so this rejects an absolute ref and any
// ref that cleans to somewhere outside repoRoot — without it, a
// committed .repo-enc.yml setting key_source to an absolute path or a
// "../"-escaping one would make `init`/`rotate-keys` read or write key
// material anywhere on disk the config author chose, not just inside
// the repository this tool is scoped to.
func resolveConfined(repoRoot, ref string) (string, error) {
	if filepath.IsAbs(ref) {
		return "", fmt.Errorf("key_source %q must be repo-relative, not absolute", ref)
	}
	joined := filepath.Join(repoRoot, ref)
	root := filepath.Clean(repoRoot)
	if joined != root && !strings.HasPrefix(joined, root+string(filepath.Separator)) {
		return "", fmt.Errorf("key_source %q escapes the repository root", ref)
	}
	return joined, nil
}

// New returns the registered backend for name (e.g. from Config.KeyBackend).
func New(name string) (Backend, error) {
	b, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("keybackend: unknown backend %q", name)
	}
	return b, nil
}
