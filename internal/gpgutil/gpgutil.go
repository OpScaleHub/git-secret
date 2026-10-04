// Package gpgutil shells out to the gpg binary to list local keys and to
// wrap/unwrap the small data-encryption-key that keybackend's
// "gpg" backend stores. It mirrors internal/gitutil's exec-wrapper
// pattern: a fixed binary name, captured stdout/stderr, stderr-annotated
// errors.
package gpgutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

// ValidFingerprint reports whether s is a full GPG key fingerprint (40
// hex characters for a v4 key, 64 for v5) rather than a short key ID,
// email, or other ambiguous selector. gpg accepts all of those as a
// --recipient value, resolved against the local keyring/keyserver at
// encrypt time — which is exactly the risk: if that resolution is
// ambiguous or an attacker can influence which key a short ID or email
// resolves to locally, the repo's data-encryption key can be wrapped to
// the wrong key. Only a full fingerprint pins the exact key with no
// ambiguity, so config/CLI recipient input is required to be one.
func ValidFingerprint(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
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
	return EncryptContext(context.Background(), plaintext, recipients)
}

// EncryptContext is Encrypt with a cancellation/deadline context -- the
// gpg process is killed if ctx is done first. Used by callers that face
// untrusted input on a request path (keyfold ui) and must bound
// how long a single seal can run.
func EncryptContext(ctx context.Context, plaintext []byte, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("gpgutil: encrypt: no recipients given")
	}
	args := []string{"--batch", "--yes", "--trust-model", "always", "--armor", "--encrypt"}
	for _, kr := range ExtraPublicKeyrings {
		args = append(args, "--keyring", kr)
	}
	for _, r := range recipients {
		args = append(args, "--recipient", r)
	}
	out, err := runCtx(ctx, plaintext, args...)
	if err != nil {
		return nil, fmt.Errorf("gpgutil: encrypt: %w", err)
	}
	return out, nil
}

// ImportSecretKey imports an armored private key (and any public keys
// bundled with it) into the current GNUPGHOME, so this process's own
// gpg (and gpg-agent) can subsequently decrypt blobs wrapped to it.
// Intended for a process's one-time startup import (e.g.
// keyfold-controller importing its own dedicated identity from a
// mounted Secret) into an isolated, process-private GNUPGHOME set up
// by the caller — never the operator's own keyring.
func ImportSecretKey(armored []byte) error {
	if _, err := run(armored, "--batch", "--import"); err != nil {
		return fmt.Errorf("gpgutil: import secret key: %w", err)
	}
	return nil
}

// ImportPublicKey imports an armored public key into the current
// GNUPGHOME so it can be used as an --encrypt recipient. Public keys are
// not secret; this is safe to call with keyring-provided material.
func ImportPublicKey(armored []byte) error {
	if _, err := run(armored, "--batch", "--import"); err != nil {
		return fmt.Errorf("gpgutil: import public key: %w", err)
	}
	return nil
}

// ExportPublicKey returns the ASCII-armored public key for fpr from the
// current GNUPGHOME. Public keys are not secret -- this is used to hand a
// controller's own public key to whoever needs to seal GitSecrets to it,
// without exposing anything sensitive.
func ExportPublicKey(fpr string) ([]byte, error) {
	if !ValidFingerprint(fpr) {
		return nil, fmt.Errorf("gpgutil: %q is not a full fingerprint", fpr)
	}
	out, err := run(nil, "--batch", "--armor", "--export", fpr)
	if err != nil {
		return nil, fmt.Errorf("gpgutil: export public key: %w", err)
	}
	if !bytes.Contains(out, []byte("BEGIN PGP PUBLIC KEY BLOCK")) {
		return nil, fmt.Errorf("gpgutil: no public key found for %s", fpr)
	}
	return out, nil
}

// ExtraPublicKeyrings are additional keybox files consulted (alongside the
// current GNUPGHOME's own keyring) for recipient *public* keys when
// encrypting. Process-wide: a CLI sets it once, before sealing, from public
// keys it was handed (see NewScratchPublicKeyring) -- so those keys are
// usable without ever being imported into the operator's own keyring.
var ExtraPublicKeyrings []string

// ScratchPublicKeyring is a throwaway GPG home holding only public keys,
// whose keybox can be listed in ExtraPublicKeyrings.
type ScratchPublicKeyring struct {
	home string
}

// NewScratchPublicKeyring creates an empty scratch keyring. Close removes it.
func NewScratchPublicKeyring() (*ScratchPublicKeyring, error) {
	home, err := os.MkdirTemp("", "keyfold-pubring-")
	if err != nil {
		return nil, fmt.Errorf("gpgutil: create scratch keyring: %w", err)
	}
	if err := os.Chmod(home, 0o700); err != nil {
		os.RemoveAll(home)
		return nil, err
	}
	return &ScratchPublicKeyring{home: home}, nil
}

// Keybox is the keybox file to pass in ExtraPublicKeyrings.
func (k *ScratchPublicKeyring) Keybox() string { return filepath.Join(k.home, "pubring.kbx") }

// Close stops the scratch home's agent (if one started) and deletes it.
func (k *ScratchPublicKeyring) Close() error {
	_ = exec.Command("gpgconf", "--homedir", k.home, "--kill", "all").Run()
	return os.RemoveAll(k.home)
}

// ImportFor imports one armored public key and requires that it is exactly
// the primary key fpr -- not a different key, and not extra keys riding
// along in the same block. The check runs in an empty staging home first,
// so it never depends on (or pollutes) what the scratch keyring already
// holds: a keyring entry's publicKey is only trusted to be the key its
// fingerprint names.
func (k *ScratchPublicKeyring) ImportFor(fpr string, armored []byte) error {
	if err := VerifyPublicKeyBlock(fpr, armored); err != nil {
		return err
	}
	return k.importRaw(armored)
}

// VerifyPublicKeyBlock checks, in an empty throwaway home, that armored is
// exactly the public key fpr and nothing else.
func VerifyPublicKeyBlock(fpr string, armored []byte) error {
	if !ValidFingerprint(fpr) {
		return fmt.Errorf("gpgutil: %q is not a full fingerprint", fpr)
	}
	staging, err := NewScratchPublicKeyring()
	if err != nil {
		return err
	}
	defer staging.Close()
	if err := staging.importRaw(armored); err != nil {
		return fmt.Errorf("gpgutil: import public key for %s: %w", fpr, err)
	}
	got, err := staging.fingerprints()
	if err != nil {
		return err
	}
	if len(got) != 1 || !got[strings.ToUpper(fpr)] {
		names := make([]string, 0, len(got))
		for f := range got {
			names = append(names, f)
		}
		return fmt.Errorf("gpgutil: the publicKey given for %s contains %v, not exactly that key", fpr, names)
	}
	return nil
}

func (k *ScratchPublicKeyring) importRaw(armored []byte) error {
	cmd := exec.Command(Binary, "--homedir", k.home, "--batch", "--import")
	cmd.Stdin = bytes.NewReader(armored)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (k *ScratchPublicKeyring) fingerprints() (map[string]bool, error) {
	out, err := exec.Command(Binary, "--homedir", k.home, "--batch", "--with-colons", "--list-keys").Output()
	if err != nil {
		// An empty, never-used home has no keybox yet.
		if _, statErr := os.Stat(k.Keybox()); os.IsNotExist(statErr) {
			return map[string]bool{}, nil
		}
		return nil, fmt.Errorf("gpgutil: list scratch keyring: %w", err)
	}
	fps := map[string]bool{}
	inPrimary := false
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, ":")
		switch f[0] {
		case "pub":
			inPrimary = true
		case "sub":
			inPrimary = false
		case "fpr":
			if inPrimary && len(f) > 9 {
				fps[strings.ToUpper(f[9])] = true
				inPrimary = false
			}
		}
	}
	return fps, nil
}

// CountRecipients returns how many public-key recipients an armored GPG
// message is encrypted to, counting its pubkey-enc packets. It does not
// resolve them to fingerprints -- the packet carries a recipient's
// encryption-subkey ID, not the primary-key fingerprint -- so this is a
// count check only (see sealer.VerifyRecipients).
//
// --list-only is load-bearing: plain --list-packets tries to decrypt, so
// with a recipient's secret key present it unwraps the session key (a
// private-key operation on the admission path), and without one it exits
// 2 and the count is lost. With --list-only gpg only walks the packet
// headers: no secret key, no agent, no decryption, whoever's keyring this
// is.
//
// It runs under a 5s timeout: this parses attacker-controlled input (the
// GitSecret's encryptedKey) on the admission webhook path, and a crafted
// packet must not be able to hang the handler.
func CountRecipients(armored []byte) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := runCtx(ctx, armored, "--batch", "--list-only", "--list-packets")
	if err != nil {
		return 0, fmt.Errorf("gpgutil: list-packets: %w", err)
	}
	n := bytes.Count(out, []byte("pubkey enc packet"))
	if n == 0 {
		return 0, fmt.Errorf("gpgutil: no pubkey-enc packets in message")
	}
	return n, nil
}

// run executes gpg with args, piping stdin (if non-nil) and capturing
// stdout/stderr. --trust-model always (on Encrypt) bypasses gpg's own
// web-of-trust confirmation prompt, which would otherwise hang forever
// with no tty attached in a hook or CI context — acceptable here because
// recipient identity is the user's own config choice (a fingerprint
// pinned in .repo-enc.yml), not something gpg's trust model needs to
// independently vouch for.
func run(stdin []byte, args ...string) ([]byte, error) {
	return runCtx(context.Background(), stdin, args...)
}

// runCtx is run with a cancellation/timeout context -- the process is
// killed if ctx is done before it exits.
func runCtx(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, Binary, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s timed out: %w", Binary, ctx.Err())
		}
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
