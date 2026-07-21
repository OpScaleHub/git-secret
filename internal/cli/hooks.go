package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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
	stagedSet := make(map[string]bool, len(staged))
	for _, p := range staged {
		stagedSet[p] = true
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

	// k8s_secret_paths is a separate, per-value encryption policy: there's
	// no whole file to transparently swap in ciphertext for (the user
	// must run `kubectl secret encrypt-value` themselves), so the only
	// thing pre-commit can do here is block a commit that would land a
	// value that's neither ciphertext nor explicitly allowlisted plaintext.
	var k8sProblems []string
	for _, kp := range c.Config.K8sSecretPaths {
		if !stagedSet[kp] {
			continue
		}
		data, err := gitutil.ReadStaged(c.RepoRoot, kp)
		if err != nil {
			return fmt.Errorf("pre-commit: read staged %s: %w", kp, err)
		}
		leaks, err := lintK8sManifest(data, kp, key, c.Config.K8sPlaintextKeys[kp])
		if err != nil {
			return fmt.Errorf("pre-commit: lint %s: %w", kp, err)
		}
		k8sProblems = append(k8sProblems, leaks...)
	}
	if len(k8sProblems) > 0 {
		return fmt.Errorf("pre-commit: refusing commit, unencrypted/invalid k8s_secret_paths value(s):\n  %s", strings.Join(k8sProblems, "\n  "))
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
// plaintext — the last line of defense if a commit ever bypassed
// pre-commit (e.g. `git commit --no-verify`).
//
// It checks two things: HEAD itself (the authenticated Verify() check,
// which needs the key and needs it to actually work), and — reading
// git's pre-push ref-update protocol from stdin (lines of "<local ref>
// <local oid> <remote ref> <remote oid>") — every commit in each pushed
// range that the remote doesn't already have. HEAD alone isn't enough: a
// plaintext commit earlier in the range, with a later commit that only
// fixes HEAD, would otherwise reach the remote undetected. The range
// walk uses structural envelope validation rather than full
// authentication (see crypto.ParseEnvelope's doc) since an old commit
// may be sealed under a key that's since rotated away.
//
// stdin may be empty (as when this is called directly rather than via
// git's real pre-push invocation, e.g. in tests) — the range walk is
// then simply skipped and only the HEAD check applies.
func (c *Context) HookPrePush(stdin io.Reader) error {
	problems, err := c.Verify()
	if err != nil {
		return err
	}

	updates, err := parsePrePushUpdates(stdin)
	if err != nil {
		return fmt.Errorf("pre-push: %w", err)
	}
	seen := map[string]bool{}
	for _, u := range updates {
		if gitutil.IsZeroOID(u.localOID) {
			continue // ref deletion: nothing new is being pushed
		}
		revs, err := gitutil.RevList(c.RepoRoot, u.remoteOID, u.localOID)
		if err != nil {
			return err
		}
		for _, rev := range revs {
			if seen[rev] {
				continue
			}
			seen[rev] = true
			found, err := c.verifyCommitStructurally(rev)
			if err != nil {
				return err
			}
			problems = append(problems, found...)
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("refusing to push: found plaintext in commit(s) being pushed:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// prePushUpdate is one line of git's pre-push ref-update stdin protocol.
type prePushUpdate struct {
	localRef, localOID, remoteRef, remoteOID string
}

// parsePrePushUpdates reads git's pre-push hook stdin protocol: one
// "<local ref> <local oid> <remote ref> <remote oid>" line per ref being
// updated. An empty/absent stdin yields no updates, not an error, so
// direct callers that don't have a real push to describe (tests, or any
// future non-hook caller) don't need to fabricate one.
func parsePrePushUpdates(stdin io.Reader) ([]prePushUpdate, error) {
	if stdin == nil {
		return nil, nil
	}
	var updates []prePushUpdate
	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, fmt.Errorf("malformed ref-update line: %q", line)
		}
		updates = append(updates, prePushUpdate{fields[0], fields[1], fields[2], fields[3]})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	return updates, nil
}

// verifyCommitStructurally checks the paths a single commit adds or
// modifies (per gitutil.ChangedPaths) against the config committed in
// that same commit, using structural envelope validation rather than
// full authenticated decryption — see crypto.ParseEnvelope's doc for why
// full auth isn't reliable across a possible key rotation.
func (c *Context) verifyCommitStructurally(rev string) ([]string, error) {
	changed, err := gitutil.ChangedPaths(c.RepoRoot, rev)
	if err != nil {
		return nil, err
	}
	if len(changed) == 0 {
		return nil, nil
	}
	cfg, err := configAtRevision(c.RepoRoot, rev)
	if err != nil {
		if gitutil.IsMissingPath(err) {
			return nil, nil
		}
		return nil, err
	}

	short := rev
	if len(short) > 12 {
		short = short[:12]
	}

	var problems []string
	for _, p := range changed {
		isK8s := containsString(cfg.K8sSecretPaths, p)
		matched := false
		if !isK8s {
			matched, err = cfg.Matches(p)
			if err != nil {
				return problems, err
			}
		}
		if !matched && !isK8s {
			continue
		}
		data, err := gitutil.ReadAtRev(c.RepoRoot, rev, p)
		if err != nil {
			if gitutil.IsMissingPath(err) {
				continue
			}
			return problems, err
		}
		if isK8s {
			leaks, err := lintK8sManifest(data, p, nil, cfg.K8sPlaintextKeys[p])
			if err != nil {
				return problems, fmt.Errorf("%s@%s: %w", p, short, err)
			}
			for _, l := range leaks {
				problems = append(problems, fmt.Sprintf("%s@%s", l, short))
			}
			continue
		}
		if err := crypto.ParseEnvelope(data); err != nil {
			problems = append(problems, fmt.Sprintf("%s@%s: %v", p, short, err))
		}
	}
	if cfg.KeyBackend == "file" && containsString(changed, cfg.KeySource) {
		problems = append(problems, fmt.Sprintf("%s@%s: raw file-backend key must never be committed", cfg.KeySource, short))
	}
	return problems, nil
}
