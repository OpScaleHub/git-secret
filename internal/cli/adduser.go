package cli

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/internal/config"
	"github.com/OpScaleHub/git-secret/internal/crypto"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// AddUserResult reports what AddUser did.
type AddUserResult struct {
	Recipient      string
	AlreadyPresent bool
}

// AddUser grants recipient (a GPG fingerprint) access to the repo's
// existing key, only valid when KeyBackend is "gpg". Unlike RemoveUser,
// this is cheap: the data-encryption-key itself is unchanged, only
// re-wrapped for the expanded recipient list, so no file needs
// re-encrypting.
func (c *Context) AddUser(recipient string) (*AddUserResult, error) {
	if c.Config.KeyBackend != "gpg" {
		return nil, fmt.Errorf("adduser: only supported with key_backend: gpg")
	}
	for _, r := range c.Config.GPGRecipients {
		if r == recipient {
			return &AddUserResult{Recipient: recipient, AlreadyPresent: true}, nil
		}
	}

	// Proves the caller already has legitimate access before granting it
	// to someone else.
	dek, err := c.Key()
	if err != nil {
		return nil, fmt.Errorf("adduser: %w", err)
	}

	updated := append(append([]string{}, c.Config.GPGRecipients...), recipient)
	wrapped, err := gpgutil.Encrypt(dek, updated)
	if err != nil {
		return nil, fmt.Errorf("adduser: %w", err)
	}
	if err := crypto.WriteFileAtomic(c.abs(c.Config.KeySource), wrapped, 0o644); err != nil {
		return nil, fmt.Errorf("adduser: write %s: %w", c.Config.KeySource, err)
	}

	newCfg := *c.Config
	newCfg.GPGRecipients = updated
	if err := config.Save(c.RepoRoot, &newCfg); err != nil {
		return nil, fmt.Errorf("adduser: save config: %w", err)
	}
	c.Config = &newCfg

	return &AddUserResult{Recipient: recipient}, nil
}
