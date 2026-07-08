package cli

import (
	"os"

	"github.com/OpScaleHub/git-secret/internal/crypto"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
)

// FileState describes what Status found for one matched file.
type FileState struct {
	Path  string
	State string // "plaintext", "encrypted", or "unreadable"
	// Hidden is true when the skip-worktree bit is set on Path, meaning
	// `git status` won't report it as modified even though it's
	// currently plaintext on disk while the index holds ciphertext —
	// set by Unlock/DecryptPaths, cleared by Lock/EncryptPaths.
	Hidden bool
}

const (
	StatePlaintext  = "plaintext"
	StateEncrypted  = "encrypted"
	StateUnreadable = "unreadable"
)

// Status reports the current on-disk state of every config-matched file,
// without modifying anything. This is what both `status` and lock/unlock
// `--dry-run` use to preview their effect.
func (c *Context) Status() ([]FileState, error) {
	paths, err := c.MatchedFiles()
	if err != nil {
		return nil, err
	}
	out := make([]FileState, 0, len(paths))
	for _, p := range paths {
		hidden, _ := gitutil.IsSkipWorktree(c.RepoRoot, p) // best-effort; false (and no error surfaced) for untracked files

		data, err := os.ReadFile(c.abs(p))
		if err != nil {
			out = append(out, FileState{Path: p, State: StateUnreadable, Hidden: hidden})
			continue
		}
		if crypto.IsEnvelope(data) {
			out = append(out, FileState{Path: p, State: StateEncrypted, Hidden: hidden})
		} else {
			out = append(out, FileState{Path: p, State: StatePlaintext, Hidden: hidden})
		}
	}
	return out, nil
}
