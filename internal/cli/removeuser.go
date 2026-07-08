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
	newCfg := *c.Config
	newCfg.GPGRecipients = updated
	if err := config.Save(c.RepoRoot, &newCfg); err != nil {
		return nil, fmt.Errorf("removeuser: save config: %w", err)
	}
	c.Config = &newCfg

	backend, err := resolveBackend(c.Config)
	if err != nil {
		return nil, fmt.Errorf("removeuser: %w", err)
	}
	c.Backend = backend

	rotateResult, err := c.RotateKeys()
	if err != nil {
		return nil, fmt.Errorf("removeuser: rotate-keys: %w", err)
	}
	return &RemoveUserResult{Recipient: recipient, RotateResult: rotateResult}, nil
}
