package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/OpScaleHub/git-secret/crypto"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
	"github.com/OpScaleHub/git-secret/keybackend"
)

// HookNames are the git hooks Init installs. Order doesn't matter here;
// each is independent.
var HookNames = []string{"pre-commit", "post-checkout", "post-merge", "pre-push"}

// HookPreCommit rewrites the *index* entry (not the working tree file) of
// every staged, config-matched file to point at its encrypted blob, so
// the commit records ciphertext while the user's working copy stays
// plaintext. Already-encrypted staged content (e.g. re-staged after a
// previous hook run) is left alone.
func (c *Context) HookPreCommit() error {
	key, err := c.Key()
	if err != nil {
		return fmt.Errorf("pre-commit: %w (run `repo-enc unlock` or configure a key first)", err)
	}

	staged, err := gitutil.StagedFiles(c.RepoRoot)
	if err != nil {
		return err
	}
	for _, p := range staged {
		matched, err := c.Config.Matches(p)
		if err != nil {
			return err
		}
		if !matched {
			continue
		}
		data, err := gitutil.ReadStaged(c.RepoRoot, p)
		if err != nil {
			return fmt.Errorf("pre-commit: read staged %s: %w", p, err)
		}
		if crypto.IsEnvelope(data) {
			continue
		}
		env, err := crypto.Seal(crypto.Default, data, key, []byte(p))
		if err != nil {
			return fmt.Errorf("pre-commit: encrypt %s: %w", p, err)
		}
		sha, err := gitutil.HashObjectWrite(c.RepoRoot, env)
		if err != nil {
			return fmt.Errorf("pre-commit: store blob for %s: %w", p, err)
		}
		if err := gitutil.UpdateIndexBlob(c.RepoRoot, sha, p); err != nil {
			return fmt.Errorf("pre-commit: stage encrypted %s: %w", p, err)
		}
		// update-index --cacheinfo (inside UpdateIndexBlob) replaces the
		// index entry outright, which silently clears any skip-worktree
		// bit a prior `unlock` had set on this path. Re-apply it: the
		// working tree is still plaintext post-commit (by design, it's
		// never touched here), so it should stay hidden from `git
		// status` exactly as it was before the commit. Best-effort.
		_ = gitutil.SetSkipWorktree(c.RepoRoot, p, true)
	}
	return nil
}

// HookPostCheckout decrypts working-tree copies of config-matched files
// that checkout just populated with ciphertext (because that's what's
// committed). It never fails the checkout itself: a missing key just
// means the tree is left encrypted, with a note to the user.
func (c *Context) HookPostCheckout() error {
	return c.decryptAfterGitOperation()
}

// HookPostMerge is identical to HookPostCheckout: a merge/pull can also
// bring in new ciphertext that needs decrypting into the working tree.
func (c *Context) HookPostMerge() error {
	return c.decryptAfterGitOperation()
}

func (c *Context) decryptAfterGitOperation() error {
	paths, err := c.MatchedFiles()
	if err != nil {
		return err
	}
	if _, err := c.DecryptPaths(paths); err != nil {
		if errors.Is(err, keybackend.ErrKeyNotFound) {
			fmt.Fprintln(os.Stderr, "repo-enc: no key configured yet — files left encrypted (run `repo-enc unlock` once a key is available)")
			return nil
		}
		return err
	}
	return nil
}

// HookPrePush blocks the push if any config-matched file is committed as
// plaintext at HEAD — the last line of defense if a commit ever bypassed
// pre-commit (e.g. `git commit --no-verify`).
func (c *Context) HookPrePush() error {
	problems, err := c.Verify()
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("refusing to push: committed as plaintext: %s", strings.Join(problems, ", "))
	}
	return nil
}
