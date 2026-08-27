package main

import (
	"fmt"
	"os"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// keyringFile is the on-disk format for --keyring: a plain list of the
// recipients a repo/cluster normally seals to, so `git-secret-seal` can
// resolve them instead of the caller retyping every fingerprint. It is not
// secret (public keys / fingerprints only) and is meant to be committed
// alongside the GitSecrets it applies to.
//
//	recipients:
//	  - fingerprint: AAAA...   # 40 or 64 hex
//	    role: controller       # human|controller|recovery|deprecated (optional)
//	  - fingerprint: BBBB...
//	    role: recovery
type keyringFile struct {
	Recipients []struct {
		Fingerprint string `json:"fingerprint"`
		Role        string `json:"role,omitempty"`
	} `json:"recipients"`
}

// loadKeyring reads path and returns its fingerprints (validated) and any
// roles keyed by upper-case fingerprint.
func loadKeyring(path string) (fingerprints []string, roles map[string]v1alpha1.RecipientRole, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read keyring %s: %w", path, err)
	}
	var kr keyringFile
	if err := sigsyaml.Unmarshal(raw, &kr); err != nil {
		return nil, nil, fmt.Errorf("parse keyring %s: %w", path, err)
	}
	if len(kr.Recipients) == 0 {
		return nil, nil, fmt.Errorf("keyring %s lists no recipients", path)
	}
	roles = map[string]v1alpha1.RecipientRole{}
	seen := map[string]bool{}
	for i, r := range kr.Recipients {
		if !gpgutil.ValidFingerprint(r.Fingerprint) {
			return nil, nil, fmt.Errorf("keyring %s: recipients[%d].fingerprint %q is not a full GPG fingerprint", path, i, r.Fingerprint)
		}
		key := upperFP(r.Fingerprint)
		if seen[key] {
			continue
		}
		seen[key] = true
		fingerprints = append(fingerprints, r.Fingerprint)
		if r.Role != "" {
			role := v1alpha1.RecipientRole(r.Role)
			if !v1alpha1.ValidRecipientRole(role) {
				return nil, nil, fmt.Errorf("keyring %s: recipients[%d].role %q is not valid (human|controller|recovery|deprecated)", path, i, r.Role)
			}
			roles[key] = role
		}
	}
	return fingerprints, roles, nil
}

func upperFP(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 32
		}
	}
	return string(b)
}
