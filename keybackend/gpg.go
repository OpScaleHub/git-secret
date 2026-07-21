package keybackend

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	renccrypto "github.com/OpScaleHub/git-secret/crypto"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// GPGBackend stores the key GPG-encrypted ("wrapped") to one or more
// recipients, resolved relative to the repo root unless ref is already
// absolute. Unlike FileBackend's raw key, this wrapped blob is meant to
// be committed: only a matching GPG private key can unwrap it, so
// `init` does not add it to .gitignore.
type GPGBackend struct {
	// Recipients are GPG fingerprints the key is wrapped to. Required
	// by Generate; unused by Get, since gpg's own keyring/agent decides
	// which local secret key opens the blob, independent of who else
	// it's also wrapped to.
	Recipients []string
}

func (GPGBackend) Name() string { return "gpg" }

func (b GPGBackend) WithRecipients(recipients []string) Backend {
	b.Recipients = recipients
	return b
}

func (GPGBackend) resolve(repoRoot, ref string) (string, error) {
	return resolveConfined(repoRoot, ref)
}

func (b GPGBackend) Get(repoRoot, ref string) ([]byte, error) {
	if !gpgutil.Available() {
		return nil, fmt.Errorf("keybackend(gpg): %w", gpgutil.ErrNotInstalled)
	}
	path, err := b.resolve(repoRoot, ref)
	if err != nil {
		return nil, fmt.Errorf("keybackend(gpg): %w", err)
	}
	wrapped, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, path)
		}
		return nil, fmt.Errorf("keybackend(gpg): read %s: %w", path, err)
	}
	key, err := gpgutil.Decrypt(wrapped)
	if err != nil {
		if strings.Contains(err.Error(), "No secret key") {
			// The blob exists but no local secret key can open it (e.g.
			// a stranger cloned the repo). Functionally this is the same
			// "you need a key set up for this repo" situation as a
			// missing file, so it gets the same ErrKeyNotFound/exit-2
			// treatment rather than a generic error.
			return nil, fmt.Errorf("%w: no local GPG secret key can decrypt %s", ErrKeyNotFound, path)
		}
		return nil, fmt.Errorf("keybackend(gpg): %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("keybackend(gpg): %s: invalid key length %d (expected %d bytes)", path, len(key), KeySize)
	}
	return key, nil
}

func (b GPGBackend) Generate(repoRoot, ref string) ([]byte, error) {
	if !gpgutil.Available() {
		return nil, fmt.Errorf("keybackend(gpg): %w", gpgutil.ErrNotInstalled)
	}
	if len(b.Recipients) == 0 {
		return nil, fmt.Errorf("keybackend(gpg): no recipients configured (set gpg_recipients in .repo-enc.yml)")
	}
	path, err := b.resolve(repoRoot, ref)
	if err != nil {
		return nil, fmt.Errorf("keybackend(gpg): %w", err)
	}
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("keybackend(gpg): generate key: %w", err)
	}
	wrapped, err := gpgutil.Encrypt(key, b.Recipients)
	if err != nil {
		return nil, fmt.Errorf("keybackend(gpg): %w", err)
	}
	// The wrapped blob is meant to be committed, so unlike FileBackend's
	// locked-down 0o700/0o600, normal permissions are correct here — its
	// secrecy comes from GPG, not the filesystem.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("keybackend(gpg): create key dir: %w", err)
	}
	if err := renccrypto.WriteFileAtomic(path, wrapped, 0o644); err != nil {
		return nil, fmt.Errorf("keybackend(gpg): write %s: %w", path, err)
	}
	return key, nil
}
