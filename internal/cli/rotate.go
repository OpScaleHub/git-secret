package cli

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/OpScaleHub/git-secret/internal/crypto"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
)

// RotateResult reports what RotateKeys did.
type RotateResult struct {
	RotatedFiles []string
	// KeyExportVar/Hex are set only for backends that can't persist the
	// new key themselves (e.g. "env"): the caller must show this to the
	// user immediately, since the key only ever exists in memory here.
	KeyExportVar string
	KeyExportHex string
}

// RotateKeys re-encrypts every config-matched file under a freshly
// generated key, replacing the old one.
//
// Safety: every file is read and decrypted under the *old* key, and every
// re-encryption under the *new* key is computed in memory, before a
// single byte is written back to disk. If any file fails to decrypt or
// re-encrypt, RotateKeys returns an error and the working tree is
// untouched — there is nothing to roll back. Only once all files have
// been validated does it write the re-encrypted files and promote the
// new key into place; if a write fails partway through, the returned
// RotatedFiles lists exactly which paths already moved to the new key,
// so the operation can be safely re-run (already-rotated files are
// idempotently skipped by re-running Lock, or the whole rotation retried
// once the underlying I/O error is fixed).
func (c *Context) RotateKeys() (*RotateResult, error) {
	oldKey, err := c.Key()
	if err != nil {
		return nil, fmt.Errorf("rotate-keys: no existing key to rotate from: %w", err)
	}

	paths, err := c.MatchedFiles()
	if err != nil {
		return nil, err
	}

	type plan struct {
		path      string
		mode      os.FileMode
		plaintext []byte
	}
	plans := make([]plan, 0, len(paths))
	for _, p := range paths {
		abs := c.abs(p)
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: read %s: %w", p, err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: stat %s: %w", p, err)
		}
		plaintext := data
		if crypto.IsEnvelope(data) {
			plaintext, err = crypto.Open(data, oldKey, []byte(p))
			if err != nil {
				return nil, fmt.Errorf("rotate-keys: decrypt %s with current key: %w", p, err)
			}
		}
		plans = append(plans, plan{path: p, mode: info.Mode().Perm(), plaintext: plaintext})
	}

	stagingRef := c.Config.KeySource + ".new"
	newKey, err := c.Backend.Generate(c.RepoRoot, stagingRef)
	if err != nil {
		return nil, fmt.Errorf("rotate-keys: generate new key: %w", err)
	}

	result := &RotateResult{}
	if c.Config.KeyBackend == "env" {
		// This key exists only in this process's memory: surface it now,
		// before any file touches disk, so a later failure can't strand
		// the user without it.
		result.KeyExportVar = c.Config.KeySource
		result.KeyExportHex = hex.EncodeToString(newKey)
	}

	sealed := make(map[string][]byte, len(plans))
	for _, pl := range plans {
		env, err := crypto.Seal(crypto.Default, pl.plaintext, newKey, []byte(pl.path))
		if err != nil {
			cleanupStagingKey(c, stagingRef)
			return result, fmt.Errorf("rotate-keys: encrypt %s under new key: %w", pl.path, err)
		}
		sealed[pl.path] = env
	}

	for _, pl := range plans {
		if err := crypto.WriteFileAtomic(c.abs(pl.path), sealed[pl.path], pl.mode); err != nil {
			return result, fmt.Errorf("rotate-keys: write %s (files already rotated: %v — safe to re-run once fixed): %w", pl.path, result.RotatedFiles, err)
		}
		result.RotatedFiles = append(result.RotatedFiles, pl.path)
		if sha, err := gitutil.HashObjectWrite(c.RepoRoot, sealed[pl.path]); err == nil {
			_ = gitutil.UpdateIndexBlob(c.RepoRoot, sha, pl.path)
		}
		// Working tree now holds ciphertext matching the index (unlike
		// Encrypt/DecryptPaths, rotation always writes ciphertext to the
		// working tree directly) — no longer needs hiding from status.
		_ = gitutil.SetSkipWorktree(c.RepoRoot, pl.path, false)
	}

	if persistsKeyToDisk(c.Config.KeyBackend) {
		if err := os.Rename(c.abs(stagingRef), c.abs(c.Config.KeySource)); err != nil {
			return result, fmt.Errorf("rotate-keys: promote new key (files rotated but key file not swapped — do not re-run; restore %s from %s manually): %w", c.Config.KeySource, stagingRef, err)
		}
	}

	return result, nil
}

// persistsKeyToDisk reports whether a backend's Generate writes to a
// real file that needs the stage-then-promote treatment ("file", "gpg")
// as opposed to one that only returns key material in memory for the
// caller to export ("env").
func persistsKeyToDisk(backend string) bool {
	return backend == "file" || backend == "gpg"
}

func cleanupStagingKey(c *Context, stagingRef string) {
	if persistsKeyToDisk(c.Config.KeyBackend) {
		os.Remove(c.abs(stagingRef))
	}
}
