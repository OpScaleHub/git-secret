package cli

import (
	"github.com/OpScaleHub/git-secret/crypto"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
)

// Verify checks that every config-matched file, as committed at HEAD, is
// a valid encrypted envelope. It never looks at the working tree, since
// plaintext there is expected while unlocked — the thing that must never
// happen is plaintext landing in git history. Files that don't exist yet
// at HEAD (never committed) are skipped, not flagged.
//
// The returned slice is the set of paths committed as plaintext; a
// non-empty result means history has leaked a secret and `verify` should
// exit non-zero.
func (c *Context) Verify() ([]string, error) {
	paths, err := c.MatchedFiles()
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, p := range paths {
		data, err := gitutil.ReadAtRev(c.RepoRoot, "HEAD", p)
		if err != nil {
			if gitutil.IsMissingPath(err) {
				continue
			}
			return problems, err
		}
		if !crypto.IsEnvelope(data) {
			problems = append(problems, p)
		}
	}
	return problems, nil
}
