package cli

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/crypto"
	"github.com/OpScaleHub/git-secret/internal/config"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
)

// Verify checks that every config-matched file and every k8s_secret_paths
// manifest, as committed at HEAD, is genuinely and authentically
// encrypted. It never looks at the working tree or index — only at what
// HEAD actually contains — because a plaintext working copy is expected
// while unlocked, and staged-but-uncommitted state (a staged deletion, a
// dirty .repo-enc.yml edit) must not be able to hide what's really in
// history. See VerifyAtRevision for exactly what "genuinely encrypted"
// means and why it needs the key.
//
// The returned slice describes every problem found; a non-empty result
// means history has leaked a secret (or the raw file-backend key) and
// `verify` should exit non-zero.
func (c *Context) Verify() ([]string, error) {
	return c.VerifyAtRevision("HEAD")
}

// VerifyAtRevision is Verify, generalized to any revision. It loads
// .repo-enc.yml as committed *at rev* (not off disk), so a dirty or
// stale working-tree config can't change what gets enforced, and it
// authenticates every matched blob with crypto.Open — not the old
// magic-prefix-only IsEnvelope check, which accepted any four bytes
// "RENC" followed by garbage (corrupted ciphertext, or literally
// handwritten fake plaintext) as proof of encryption. Authenticating
// requires the key; if it's unavailable, this fails closed (an error,
// not a false "OK") rather than silently skipping the one check that
// proves anything.
func (c *Context) VerifyAtRevision(rev string) ([]string, error) {
	cfg, err := configAtRevision(c.RepoRoot, rev)
	if err != nil {
		if gitutil.IsMissingPath(err) {
			// No .repo-enc.yml at this revision (e.g. a commit before
			// `init`): nothing to enforce yet.
			return nil, nil
		}
		return nil, err
	}
	key, err := c.Key()
	if err != nil {
		return nil, fmt.Errorf("verify: %w (proving encryption requires the key; verify fails closed rather than skipping the check)", err)
	}

	paths, err := matchedPathsAtRevision(c.RepoRoot, rev, cfg)
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, p := range paths {
		data, err := gitutil.ReadAtRev(c.RepoRoot, rev, p)
		if err != nil {
			if gitutil.IsMissingPath(err) {
				continue
			}
			return problems, err
		}
		if _, err := crypto.Open(data, key, []byte(p)); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", p, err))
		}
	}

	// The raw file-backend key must never be committed, regardless of
	// whether it happens to also match `patterns` — it's checked
	// independently of Config.Matches.
	if cfg.KeyBackend == "file" {
		if _, err := gitutil.ReadAtRev(c.RepoRoot, rev, cfg.KeySource); err == nil {
			problems = append(problems, cfg.KeySource+": raw file-backend key must never be committed")
		} else if !gitutil.IsMissingPath(err) {
			return problems, err
		}
	}

	// k8s_secret_paths manifests are a separate, independent policy from
	// Patterns/Exclude — they must be enforced here too, not just when a
	// repo also happens to list them under whole-file `patterns`.
	for _, kp := range cfg.K8sSecretPaths {
		data, err := gitutil.ReadAtRev(c.RepoRoot, rev, kp)
		if err != nil {
			if gitutil.IsMissingPath(err) {
				continue
			}
			return problems, err
		}
		leaks, err := lintK8sManifest(data, kp, key, cfg.K8sPlaintextKeys[kp])
		if err != nil {
			return problems, fmt.Errorf("verify %s: %w", kp, err)
		}
		problems = append(problems, leaks...)
	}

	return problems, nil
}

// configAtRevision loads .repo-enc.yml as committed at rev (merged with
// the machine-local global config, same as Load), instead of off disk.
func configAtRevision(repoRoot, rev string) (*config.Config, error) {
	data, err := gitutil.ReadAtRev(repoRoot, rev, config.FileName)
	if err != nil {
		return nil, err
	}
	repo, err := config.ParseBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%s at %s: %w", config.FileName, rev, err)
	}
	return config.MergeGlobal(repo)
}

// matchedPathsAtRevision lists every path in the tree committed at rev
// that cfg's patterns/exclude match — the revision-pinned equivalent of
// MatchedFiles, which reflects the working tree/index instead.
func matchedPathsAtRevision(repoRoot, rev string, cfg *config.Config) ([]string, error) {
	all, err := gitutil.LsTree(repoRoot, rev)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range all {
		ok, err := cfg.Matches(f)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, f)
		}
	}
	return out, nil
}

// containsString reports whether s is present in list.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
