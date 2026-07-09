// Package gpgutil shells out to the gpg binary to list local keys and to
// wrap/unwrap the small data-encryption-key that keybackend's
// "gpg" backend stores. It mirrors internal/gitutil's exec-wrapper
// pattern: a fixed binary name, captured stdout/stderr, stderr-annotated
// errors.
package gpgutil

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Binary is the gpg executable invoked for every operation.
var Binary = "gpg"

// ErrNotInstalled is returned by Available-gated callers when gpg isn't
// on PATH. This is an environment problem, not a "key not configured"
// problem, so callers should map it to a generic error exit code rather
// than the "key unavailable" one used for ErrKeyNotFound.
var ErrNotInstalled = errors.New("gpgutil: gpg binary not found on PATH")

// Available reports whether the gpg binary can be found on PATH.
func Available() bool {
	_, err := exec.LookPath(Binary)
	return err == nil
}

// SecretKey describes one local key as reported by gpg --list-secret-keys
// or --list-public-keys.
type SecretKey struct {
	// Fingerprint is the primary key's 40-hex fingerprint. Always use
	// this, never a short/long key ID, as the recipient identifier —
	// key IDs have real-world collision/spoofing history, fingerprints
	// effectively don't.
	Fingerprint string
	// UserIDs is one "Name <email>" string per uid record associated
	// with the key.
	UserIDs []string
}

// ListSecretKeys lists keys this keyring holds a private key for —
// candidates the user can decrypt with, used by `init`'s interactive
// picker to pick "yourself" as a recipient.
func ListSecretKeys() ([]SecretKey, error) {
	out, err := run(nil, "--batch", "--with-colons", "--list-secret-keys")
	if err != nil {
		return nil, fmt.Errorf("gpgutil: list secret keys: %w", err)
	}
	return parseColonKeys(out, "sec"), nil
}

// ListPublicKeys lists keys in the public keyring matching query (or all
// of them if query is empty) — used by `adduser` to resolve a teammate's
// already-imported public key, which this local keyring cannot decrypt
// with but can encrypt to.
func ListPublicKeys(query string) ([]SecretKey, error) {
	args := []string{"--batch", "--with-colons", "--list-public-keys"}
	if query != "" {
		args = append(args, query)
	}
	out, err := run(nil, args...)
	if err != nil {
		return nil, fmt.Errorf("gpgutil: list public keys: %w", err)
	}
	return parseColonKeys(out, "pub"), nil
}

// parseColonKeys parses gpg's --with-colons output. primaryRecord is
// "sec" or "pub" depending on which listing produced it. Each key's
// Fingerprint comes from the first "fpr" record following its primary
// record — subsequent "fpr" records belong to subkeys (following
// "ssb"/"sub" records) and are ignored, since --recipient always refers
// to the primary key.
func parseColonKeys(output []byte, primaryRecord string) []SecretKey {
	var keys []SecretKey
	var current *SecretKey
	expectPrimaryFpr := false

	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case primaryRecord:
			if current != nil {
				keys = append(keys, *current)
			}
			current = &SecretKey{}
			expectPrimaryFpr = true
		case "fpr":
			if current != nil && expectPrimaryFpr && len(fields) > 9 {
				current.Fingerprint = fields[9]
				expectPrimaryFpr = false
			}
		case "uid":
			if current != nil && len(fields) > 9 && fields[9] != "" {
				current.UserIDs = append(current.UserIDs, fields[9])
			}
		}
	}
	if current != nil {
		keys = append(keys, *current)
	}
	return keys
}

// Decrypt unwraps a gpg-encrypted blob using whatever local secret key
// (via gpg-agent) can open it.
func Decrypt(ciphertext []byte) ([]byte, error) {
	out, err := run(ciphertext, "--batch", "--quiet", "--decrypt")
	if err != nil {
		return nil, fmt.Errorf("gpgutil: decrypt: %w", err)
	}
	return out, nil
}

// Encrypt wraps plaintext (the repo's data-encryption-key) for every
// recipient (fingerprints). The result is ASCII-armored so the committed
// blob stays text-diffable, consistent with this codebase's existing
// preference for text-safe encodings over raw binary.
func Encrypt(plaintext []byte, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("gpgutil: encrypt: no recipients given")
	}
	args := []string{"--batch", "--yes", "--trust-model", "always", "--armor", "--encrypt"}
	for _, r := range recipients {
		args = append(args, "--recipient", r)
	}
	out, err := run(plaintext, args...)
	if err != nil {
		return nil, fmt.Errorf("gpgutil: encrypt: %w", err)
	}
	return out, nil
}

// run executes gpg with args, piping stdin (if non-nil) and capturing
// stdout/stderr. --trust-model always (on Encrypt) bypasses gpg's own
// web-of-trust confirmation prompt, which would otherwise hang forever
// with no tty attached in a hook or CI context — acceptable here because
// recipient identity is the user's own config choice (a fingerprint
// pinned in .repo-enc.yml), not something gpg's trust model needs to
// independently vouch for.
func run(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(Binary, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
