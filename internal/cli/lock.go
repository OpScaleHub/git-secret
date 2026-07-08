package cli

import (
	"fmt"
	"os"

	"github.com/OpScaleHub/git-secret/internal/crypto"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
)

// EncryptPaths encrypts each working-tree file in place, skipping any
// that are already a valid envelope (idempotent). Original file mode
// bits are preserved.
func (c *Context) EncryptPaths(paths []string) (touched []string, err error) {
	key, err := c.Key()
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		abs := c.abs(p)
		data, err := os.ReadFile(abs)
		if err != nil {
			return touched, fmt.Errorf("read %s: %w", p, err)
		}
		if crypto.IsEnvelope(data) {
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			return touched, fmt.Errorf("stat %s: %w", p, err)
		}
		env, err := crypto.Seal(crypto.Default, data, key, []byte(p))
		if err != nil {
			return touched, fmt.Errorf("encrypt %s: %w", p, err)
		}
		if err := crypto.WriteFileAtomic(abs, env, info.Mode().Perm()); err != nil {
			return touched, fmt.Errorf("write %s: %w", p, err)
		}
		// Working tree now matches what's tracked (ciphertext); no
		// longer needs hiding from `git status`. Best-effort: harmless
		// no-op for untracked files, and not worth failing Lock over.
		_ = gitutil.SetSkipWorktree(c.RepoRoot, p, false)
		touched = append(touched, p)
	}
	return touched, nil
}

// DecryptPaths decrypts each working-tree file in place, skipping any
// that are already plaintext (idempotent).
func (c *Context) DecryptPaths(paths []string) (touched []string, err error) {
	key, err := c.Key()
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		abs := c.abs(p)
		data, err := os.ReadFile(abs)
		if err != nil {
			return touched, fmt.Errorf("read %s: %w", p, err)
		}
		if !crypto.IsEnvelope(data) {
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			return touched, fmt.Errorf("stat %s: %w", p, err)
		}
		plain, err := crypto.Open(data, key, []byte(p))
		if err != nil {
			return touched, fmt.Errorf("decrypt %s: %w", p, err)
		}
		if err := crypto.WriteFileAtomic(abs, plain, info.Mode().Perm()); err != nil {
			return touched, fmt.Errorf("write %s: %w", p, err)
		}
		// The working tree is now intentionally plaintext while the
		// index/HEAD holds ciphertext — tell git not to report that as
		// a modification. Best-effort, see EncryptPaths.
		_ = gitutil.SetSkipWorktree(c.RepoRoot, p, true)
		touched = append(touched, p)
	}
	return touched, nil
}

// Lock encrypts every config-matched file in the working tree — the
// "end of session" command.
func (c *Context) Lock() ([]string, error) {
	paths, err := c.MatchedFiles()
	if err != nil {
		return nil, err
	}
	return c.EncryptPaths(paths)
}

// Unlock decrypts every config-matched file in the working tree — the
// "start of session" command.
func (c *Context) Unlock() ([]string, error) {
	paths, err := c.MatchedFiles()
	if err != nil {
		return nil, err
	}
	return c.DecryptPaths(paths)
}
