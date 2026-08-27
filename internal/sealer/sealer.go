// Package sealer implements the encrypt/decrypt logic shared by
// cmd/git-secret-seal (produces a GitSecret manifest) and
// internal/controller (reconciles one back into a plain Secret). It is
// deliberately pure/testable: no Kubernetes API calls, no CRD watching --
// just GitSecretSpec <-> map[string]string, built entirely on the existing
// crypto and gpgutil packages so this shares its cryptography with the
// repo-file "gpg" key backend rather than inventing a second scheme.
package sealer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sort"

	"github.com/OpScaleHub/git-secret/api/v1alpha1"
	renccrypto "github.com/OpScaleHub/git-secret/crypto"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

const keySize = 32 // chacha20poly1305.KeySize; avoids importing x/crypto here just for the constant.

// Bounds on what Unseal will process from a single object, so a malformed
// or hostile GitSecret cannot force the controller to allocate and decrypt
// an unbounded amount of data per reconcile. MaxEntries matches the CRD's
// MaxProperties marker on EncryptedData; MaxValueBytes is the base64-
// encoded envelope size and is deliberately generous (the resulting Secret
// is separately capped at ~1MiB by the apiserver).
const (
	MaxEntries    = 1024
	MaxValueBytes = 1 << 20 // 1 MiB per encoded value
)

// AAD binds one ciphertext to exactly the object/key it was sealed for, so
// an entry copied into a different GitSecret (or a renamed/moved one)
// fails AEAD authentication instead of silently decrypting somewhere else.
func aad(namespace, name, key string) []byte {
	return []byte(fmt.Sprintf("%s/%s/%s", namespace, name, key))
}

// Seal encrypts data (target Secret key -> plaintext value) into a
// GitSecretSpec, GPG-wrapping a freshly generated content key to every
// recipient (full 40/64-hex fingerprints -- see gpgutil.ValidFingerprint;
// callers are expected to have already validated these, matching
// keybackend.GPGBackend's existing "config trusts pinned fingerprints
// only" rule).
func Seal(namespace, name string, data map[string]string, recipients []string) (v1alpha1.GitSecretSpec, error) {
	if len(recipients) == 0 {
		return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: no recipients given")
	}
	for _, r := range recipients {
		if !gpgutil.ValidFingerprint(r) {
			return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: recipient %q is not a full GPG fingerprint", r)
		}
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: generate content key: %w", err)
	}

	wrappedKey, err := gpgutil.Encrypt(key, recipients)
	if err != nil {
		return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: wrap content key: %w", err)
	}

	encData := make(map[string]string, len(data))
	// Deterministic order isn't required for correctness (each entry is
	// independent), but it makes generated manifests diff-stable across
	// re-runs with unchanged input, matching this repo's existing
	// preference for reproducible output.
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		envelope, err := renccrypto.Seal(renccrypto.Default, []byte(data[k]), key, aad(namespace, name, k))
		if err != nil {
			return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: seal %q: %w", k, err)
		}
		encData[k] = base64.StdEncoding.EncodeToString(envelope)
	}

	return v1alpha1.GitSecretSpec{
		EncryptedKey:  string(wrappedKey),
		EncryptedData: encData,
	}, nil
}

// Rewrap re-encrypts spec's content key to newRecipients without touching
// EncryptedData at all -- adding or removing a recipient (a human, or the
// controller's own key during a DR/rotation event) never re-encrypts a
// single value, only this one small blob. This is the specific property
// that avoids Bitnami sealed-secrets' single-controller-keypair weakness:
// as long as at least one currently-valid recipient's key is available to
// call Rewrap with, a lost or rotated controller identity is a re-wrap
// away from recovery, not a full re-seal of every secret.
//
// The caller's local GNUPGHOME must hold a secret key that can already
// open spec.EncryptedKey -- i.e. one of the *current* recipients must run
// this, not an arbitrary outsider. newRecipients replaces the recipient
// list outright (include every recipient that should still be able to
// decrypt, not just the one being added).
func Rewrap(spec v1alpha1.GitSecretSpec, newRecipients []string) (v1alpha1.GitSecretSpec, error) {
	if spec.EncryptedKey == "" {
		return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: spec.encryptedKey is empty")
	}
	if len(newRecipients) == 0 {
		return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: no recipients given")
	}
	for _, r := range newRecipients {
		if !gpgutil.ValidFingerprint(r) {
			return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: recipient %q is not a full GPG fingerprint", r)
		}
	}

	key, err := gpgutil.Decrypt([]byte(spec.EncryptedKey))
	if err != nil {
		return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: unwrap content key: %w", err)
	}
	wrapped, err := gpgutil.Encrypt(key, newRecipients)
	if err != nil {
		return v1alpha1.GitSecretSpec{}, fmt.Errorf("sealer: rewrap content key: %w", err)
	}

	out := spec
	out.EncryptedKey = string(wrapped)
	return out, nil
}

// Unseal reverses Seal using whatever local GPG secret key (via gpg-agent
// in the caller's GNUPGHOME) can open EncryptedKey. namespace/name must
// match what Seal was called with, or every entry fails AEAD
// authentication.
func Unseal(namespace, name string, spec v1alpha1.GitSecretSpec) (map[string]string, error) {
	if spec.EncryptedKey == "" {
		return nil, fmt.Errorf("sealer: spec.encryptedKey is empty")
	}
	key, err := gpgutil.Decrypt([]byte(spec.EncryptedKey))
	if err != nil {
		return nil, fmt.Errorf("sealer: unwrap content key: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("sealer: unwrapped content key is %d bytes, expected %d", len(key), keySize)
	}

	if len(spec.EncryptedData) > MaxEntries {
		return nil, fmt.Errorf("sealer: encryptedData has %d entries, over the %d limit", len(spec.EncryptedData), MaxEntries)
	}

	data := make(map[string]string, len(spec.EncryptedData))
	for k, encoded := range spec.EncryptedData {
		if len(encoded) > MaxValueBytes {
			return nil, fmt.Errorf("sealer: %q: encoded value is %d bytes, over the %d limit", k, len(encoded), MaxValueBytes)
		}
		envelope, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("sealer: %q: not valid base64: %w", k, err)
		}
		plaintext, err := renccrypto.Open(envelope, key, aad(namespace, name, k))
		if err != nil {
			return nil, fmt.Errorf("sealer: %q: %w", k, err)
		}
		data[k] = string(plaintext)
	}
	return data, nil
}
