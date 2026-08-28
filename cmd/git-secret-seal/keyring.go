package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

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
//	    publicKey: |            # optional armored public key (still not secret)
//	      -----BEGIN PGP PUBLIC KEY BLOCK-----
//	      ...
//	  - fingerprint: BBBB...
//	    role: recovery
type keyringFile struct {
	Recipients []keyringFileEntry `json:"recipients"`
}

type keyringFileEntry struct {
	Fingerprint string `json:"fingerprint"`
	Role        string `json:"role,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
}

// loadKeyring reads a keyring from a local path or an http(s):// URL and
// returns its fingerprints (validated) and any roles keyed by upper-case
// fingerprint. A keyring is public data (fingerprints + roles, no key
// material), so an https URL -- a raw file in the repo host, or a
// controller endpoint -- is a fine source; plain http is allowed too but
// the caller still needs each recipient's public key in their local
// keyring to actually seal, so a tampered keyring fails closed at seal
// time rather than leaking anything.
func readKeyringBytes(src string) ([]byte, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return fetchKeyring(src)
	}
	return os.ReadFile(src)
}

// keyringHasPublicKeys reports whether the keyring at src carries any
// armored publicKey blocks (the signal that sealing should run against an
// isolated keyring rather than the operator's own).
func keyringHasPublicKeys(src string) (bool, error) {
	raw, err := readKeyringBytes(src)
	if err != nil {
		return false, fmt.Errorf("read keyring %s: %w", src, err)
	}
	var kr keyringFile
	if err := sigsyaml.Unmarshal(raw, &kr); err != nil {
		return false, fmt.Errorf("parse keyring %s: %w", src, err)
	}
	for _, r := range kr.Recipients {
		if strings.TrimSpace(r.PublicKey) != "" {
			return true, nil
		}
	}
	return false, nil
}

// importKeyringPubKeys imports any armored publicKey entries from the
// keyring at src into the current GNUPGHOME, so server-side sealing works
// without the operator's own keyring. Entries with no publicKey are
// skipped silently (they must already be in the keyring). Returns the
// number imported.
func importKeyringPubKeys(src string) (int, error) {
	raw, err := readKeyringBytes(src)
	if err != nil {
		return 0, fmt.Errorf("read keyring %s: %w", src, err)
	}
	var kr keyringFile
	if err := sigsyaml.Unmarshal(raw, &kr); err != nil {
		return 0, fmt.Errorf("parse keyring %s: %w", src, err)
	}
	n := 0
	for _, r := range kr.Recipients {
		if strings.TrimSpace(r.PublicKey) == "" {
			continue
		}
		if err := gpgutil.ImportPublicKey([]byte(r.PublicKey)); err != nil {
			return n, fmt.Errorf("import public key for %s: %w", r.Fingerprint, err)
		}
		n++
	}
	return n, nil
}

func loadKeyring(src string) (fingerprints []string, roles map[string]v1alpha1.RecipientRole, err error) {
	raw, err := readKeyringBytes(src)
	if err != nil {
		return nil, nil, fmt.Errorf("read keyring %s: %w", src, err)
	}
	var kr keyringFile
	if err := sigsyaml.Unmarshal(raw, &kr); err != nil {
		return nil, nil, fmt.Errorf("parse keyring %s: %w", src, err)
	}
	path := src
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

func fetchKeyring(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		// Cap redirects tightly -- a keyring URL is operator-chosen, but a
		// misbehaving host shouldn't be able to bounce the fetch around.
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after 3 redirects")
			}
			return nil
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	// Cap the body: a keyring is a handful of lines.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	return body, nil
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
