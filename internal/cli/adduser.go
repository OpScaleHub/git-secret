package cli

import (
	"fmt"
	"os"

	"github.com/OpScaleHub/git-secret/crypto"
	"github.com/OpScaleHub/git-secret/internal/config"
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
	if !gpgutil.ValidFingerprint(recipient) {
		return nil, fmt.Errorf("adduser: %q is not a full GPG fingerprint (40 or 64 hex characters) — short IDs and emails are ambiguous and not accepted", recipient)
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

	keyAbs, err := c.abs(c.Config.KeySource)
	if err != nil {
		return nil, fmt.Errorf("adduser: %w", err)
	}

	// Stage the re-wrapped key without touching the real key.gpg yet, so
	// a config-save failure below can't leave the committed key rewritten
	// for a recipient .repo-enc.yml never ends up listing — the "failed
	// command silently grants access" gap. Only after config.Save
	// succeeds is the staged key promoted into place.
	tmpKeyPath, err := crypto.StageFileAtomic(keyAbs, wrapped, 0o644)
	if err != nil {
		return nil, fmt.Errorf("adduser: stage %s: %w", c.Config.KeySource, err)
	}

	newCfg := *c.Config
	newCfg.GPGRecipients = updated
	if err := config.Save(c.RepoRoot, &newCfg); err != nil {
		os.Remove(tmpKeyPath)
		return nil, fmt.Errorf("adduser: save config: %w", err)
	}

	if err := os.Rename(tmpKeyPath, keyAbs); err != nil {
		// config.Save already succeeded, so .repo-enc.yml now lists
		// recipient -- meaning a plain re-run would short-circuit on the
		// AlreadyPresent check above without retrying this step. That's
		// still fail-safe (the committed key.gpg wasn't touched, so
		// recipient genuinely can't decrypt anything yet), but it does
		// need a human to reconcile: either move the staged file into
		// place by hand, or remove+re-add the recipient.
		return nil, fmt.Errorf("adduser: %s now lists %s but promoting the re-wrapped key failed (key.gpg was left untouched, so %s does not yet have access) -- move %s into place manually, or removeuser+adduser %s again: %w", config.FileName, recipient, recipient, tmpKeyPath, recipient, err)
	}
	c.Config = &newCfg

	return &AddUserResult{Recipient: recipient}, nil
}
