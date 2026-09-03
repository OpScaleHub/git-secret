package cli

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/crypto"
)

// Whole-file encryption additional-authenticated-data.
//
// Historically the AAD was just the repo-relative path, which binds a
// ciphertext blob to its location but not to the repository: two repos
// that share a key (a copied file-backend key, a leaked env key) have
// interchangeable blobs for the same path. When .repo-enc.yml carries a
// repo_id (every repo initialised since that was added), whole-file
// encryption uses a v2 envelope whose AAD is "<repo_id>\x1f<path>" and
// which also authenticates the envelope header -- so a blob sealed here
// fails authentication anywhere else.
//
// This does not add freshness: rolling a tracked file back to an earlier
// ciphertext version for the same path still authenticates. On the CLI
// path there is no monotonic counter to bind (no controller); see
// docs/security/threat-model.md T10.

const repoBindSep = "\x1f" // ASCII unit separator; never valid in a path

func fileBindAAD(repoID, path string) []byte {
	return []byte(repoID + repoBindSep + path)
}

// sealFile encrypts a whole file's plaintext for the repo-relative path p,
// choosing the v2 (repo-bound) envelope when the config has a repo_id and
// the v1 (path-only) envelope otherwise.
func (c *Context) sealFile(cph crypto.Cipher, plaintext, key []byte, p string) ([]byte, error) {
	if c.Config.RepoID != "" {
		return crypto.SealV2(cph, plaintext, key, fileBindAAD(c.Config.RepoID, p))
	}
	return crypto.Seal(cph, plaintext, key, []byte(p))
}

// openFile decrypts a whole-file envelope for the repo-relative path p,
// picking the AAD from the envelope's own version so a repo with a
// repo_id can still read v1 blobs left in its own history.
func (c *Context) openFile(envelope, key []byte, p string) ([]byte, error) {
	v, err := crypto.Version(envelope)
	if err != nil {
		return nil, err
	}
	aad := []byte(p)
	if v >= 2 {
		if c.Config.RepoID == "" {
			return nil, fmt.Errorf("%s: sealed repo-bound (envelope v%d) but .repo-enc.yml has no repo_id", p, v)
		}
		aad = fileBindAAD(c.Config.RepoID, p)
	}
	return crypto.Open(envelope, key, aad)
}
