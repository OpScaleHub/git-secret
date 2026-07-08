package cli

import (
	"os"

	"github.com/OpScaleHub/git-secret/internal/crypto"
)

// FileState describes what Status found for one matched file.
type FileState struct {
	Path  string
	State string // "plaintext", "encrypted", or "unreadable"
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
		data, err := os.ReadFile(c.abs(p))
		if err != nil {
			out = append(out, FileState{Path: p, State: StateUnreadable})
			continue
		}
		if crypto.IsEnvelope(data) {
			out = append(out, FileState{Path: p, State: StateEncrypted})
		} else {
			out = append(out, FileState{Path: p, State: StatePlaintext})
		}
	}
	return out, nil
}
