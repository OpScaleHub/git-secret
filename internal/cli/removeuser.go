package cli

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/internal/config"
)

// RemoveUserResult reports what RemoveUser did.
type RemoveUserResult struct {
	Recipient    string
	RotateResult *RotateResult
}

// RemoveUser revokes recipient's access, only valid when KeyBackend is
// "gpg". Unlike AddUser, this is not cheap and cannot be: the removed
// recipient already saw the old data-encryption-key, so merely dropping
// them from the wrap list wouldn't revoke anything they already have.
// RemoveUser forces a full RotateKeys — a fresh key, every matched file
// re-encrypted under it, wrapped only for the remaining recipients.
func (c *Context) RemoveUser(recipient string) (*RemoveUserResult, error) {
	if c.Config.KeyBackend != "gpg" {
		return nil, fmt.Errorf("removeuser: only supported with key_backend: gpg")
	}
	idx := -1
	for i, r := range c.Config.GPGRecipients {
		if r == recipient {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, fmt.Errorf("removeuser: %q is not a configured recipient", recipient)
	}

	updated := append(append([]string{}, c.Config.GPGRecipients[:idx]...), c.Config.GPGRecipients[idx+1:]...)
	if len(updated) == 0 {
		return nil, fmt.Errorf("removeuser: refusing to remove the last recipient (would leave the repo undecryptable by anyone)")
	}
	newCfg := *c.Config
	newCfg.GPGRecipients = updated

	// Rotate under the reduced recipient list *before* persisting the
	// config change. Saving config first (the old order) meant a failed
	// rotation could leave .repo-enc.yml claiming a recipient was removed
	// while the old key -- still valid for them -- was untouched on disk:
	// a misleading diff that looks like revocation but isn't. Rotating
	// against a throwaway Context built from newCfg, without touching c
	// or the committed config, means a rotation failure here leaves
	// everything exactly as it was: real access unchanged, config
	// unchanged, nothing to roll back.
	rotateBackend, err := resolveBackend(&newCfg)
	if err != nil {
		return nil, fmt.Errorf("removeuser: %w", err)
	}
	rotateResult, err := (&Context{RepoRoot: c.RepoRoot, Config: &newCfg, Backend: rotateBackend}).RotateKeys()
	if err != nil {
		return nil, fmt.Errorf("removeuser: rotate-keys: %w", err)
	}

	if err := config.Save(c.RepoRoot, &newCfg); err != nil {
		return nil, fmt.Errorf("removeuser: files were rotated to a key no longer wrapped for %s, but saving %s failed -- %s is already revoked; retry saving gpg_recipients=%v by hand: %w", recipient, config.FileName, recipient, updated, err)
	}
	c.Config = &newCfg
	c.Backend = rotateBackend

	return &RemoveUserResult{Recipient: recipient, RotateResult: rotateResult}, nil
}
