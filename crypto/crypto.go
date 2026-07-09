// Package crypto provides authenticated encryption for repository file
// contents. All ciphers implement the Cipher interface so new algorithms
// can be added without touching callers.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher is an authenticated (AEAD) encryption scheme. Implementations must
// be safe for concurrent use.
type Cipher interface {
	// Name identifies the cipher in a file header so decryption can select
	// the right implementation regardless of the current default.
	Name() string
	// Encrypt seals plaintext under key, authenticating aad alongside it.
	// The returned ciphertext embeds the nonce and is self-contained.
	Encrypt(plaintext, key, aad []byte) (ciphertext []byte, err error)
	// Decrypt opens a ciphertext produced by Encrypt with the same key/aad.
	Decrypt(ciphertext, key, aad []byte) (plaintext []byte, err error)
	// KeySize is the required key length in bytes.
	KeySize() int
}

// Default is the cipher used for new encryptions unless a file header
// specifies otherwise.
var Default Cipher = XChaCha20Poly1305{}

// registry maps a header name to the cipher that can decrypt it.
var registry = map[string]Cipher{
	XChaCha20Poly1305{}.Name(): XChaCha20Poly1305{},
	AESGCM{}.Name():            AESGCM{},
}

// ByName returns the registered cipher for a header name.
func ByName(name string) (Cipher, error) {
	c, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("crypto: unknown cipher %q", name)
	}
	return c, nil
}

// XChaCha20Poly1305 is the default cipher: a 24-byte random nonce makes
// nonce reuse practically impossible even without a counter, which suits
// files that are re-encrypted many times across a repo's history.
type XChaCha20Poly1305 struct{}

func (XChaCha20Poly1305) Name() string { return "xchacha20poly1305" }
func (XChaCha20Poly1305) KeySize() int { return chacha20poly1305.KeySize }

func (XChaCha20Poly1305) Encrypt(plaintext, key, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init xchacha20poly1305: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func (XChaCha20Poly1305) Decrypt(ciphertext, key, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init xchacha20poly1305: %w", err)
	}
	ns := aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("crypto: ciphertext too short")
	}
	nonce, sealed := ciphertext[:ns], ciphertext[ns:]
	plaintext, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt failed (wrong key or tampered data): %w", err)
	}
	return plaintext, nil
}

// AESGCM is a secondary, stdlib-only cipher offered for environments that
// avoid non-stdlib crypto. Uses a random 12-byte nonce.
type AESGCM struct{}

func (AESGCM) Name() string { return "aes256gcm" }
func (AESGCM) KeySize() int { return 32 }

func (AESGCM) Encrypt(plaintext, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: init gcm: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func (AESGCM) Decrypt(ciphertext, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: init gcm: %w", err)
	}
	ns := aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("crypto: ciphertext too short")
	}
	nonce, sealed := ciphertext[:ns], ciphertext[ns:]
	plaintext, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt failed (wrong key or tampered data): %w", err)
	}
	return plaintext, nil
}
