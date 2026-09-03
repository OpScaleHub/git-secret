package crypto

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// magic identifies files produced by this tool so `verify` can distinguish
// them from accidental plaintext with a matching extension.
var magic = []byte("RENC")

const (
	// envelopeV1 authenticates only the caller-supplied AAD. The envelope
	// header (magic + version + cipher name) sits outside the AEAD.
	envelopeV1 = 1
	// envelopeV2 prepends the header bytes to the AEAD's AAD, so header
	// tampering is an authentication failure rather than a downstream
	// parse error, and lets a caller bind extra identity (the CLI adds a
	// per-repository id -- see internal/cli) into the same AAD so a blob
	// is not portable between repositories that share a key.
	envelopeV2 = 2

	envelopeVersionDefault = envelopeV1
)

// Version returns the envelope-format version recorded in data, without
// decrypting or fully validating it. Callers that must supply a
// version-dependent AAD to Open (see internal/cli whole-file encryption)
// read it first.
func Version(data []byte) (int, error) {
	if len(data) < len(magic)+1 {
		return 0, fmt.Errorf("crypto: envelope too short")
	}
	if !bytes.Equal(data[:len(magic)], magic) {
		return 0, fmt.Errorf("crypto: not a recognized encrypted file (bad magic)")
	}
	return int(data[len(magic)]), nil
}

// Seal encrypts plaintext with c and wraps it in a self-describing envelope
// (magic + version + cipher name + ciphertext) so Open can later pick the
// correct cipher even if Default has changed. It writes a v1 envelope: the
// AEAD authenticates aad exactly as given, typically the file's
// repo-relative path, which binds ciphertext to its location and blocks
// swapping encrypted blobs between files.
func Seal(c Cipher, plaintext, key, aad []byte) ([]byte, error) {
	return seal(c, envelopeV1, plaintext, key, aad)
}

// SealV2 is Seal with the v2 envelope: the header bytes are folded into the
// AEAD's AAD alongside aad. Used for whole-file encryption once a
// repository has an id to bind (see internal/cli). Open transparently
// handles both versions.
func SealV2(c Cipher, plaintext, key, aad []byte) ([]byte, error) {
	return seal(c, envelopeV2, plaintext, key, aad)
}

func seal(c Cipher, version int, plaintext, key, aad []byte) ([]byte, error) {
	name := []byte(c.Name())
	if len(name) > 255 {
		return nil, fmt.Errorf("crypto: cipher name too long: %s", c.Name())
	}
	header := bytes.NewBuffer(nil)
	header.Write(magic)
	header.WriteByte(byte(version))
	header.WriteByte(byte(len(name)))
	header.Write(name)

	ciphertext, err := c.Encrypt(plaintext, key, aeadAAD(version, header.Bytes(), aad))
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(header.Bytes())
	buf.Write(ciphertext)
	return buf.Bytes(), nil
}

// aeadAAD is the additional-authenticated-data actually handed to the
// cipher: the caller's aad for v1, header || caller-aad for v2.
func aeadAAD(version int, header, callerAAD []byte) []byte {
	if version < envelopeV2 {
		return callerAAD
	}
	out := make([]byte, 0, len(header)+len(callerAAD))
	out = append(out, header...)
	out = append(out, callerAAD...)
	return out
}

// parseEnvelope validates envelope structure (magic, a supported
// version, and a cipher name registered with ByName) and returns the
// resolved cipher, the header bytes (everything before the ciphertext),
// the version, and the remaining ciphertext bytes. Shared by Open (which
// goes on to decrypt) and ParseEnvelope (which doesn't).
func parseEnvelope(envelope []byte) (c Cipher, header, ciphertext []byte, version int, err error) {
	if len(envelope) < len(magic)+2 {
		return nil, nil, nil, 0, fmt.Errorf("crypto: envelope too short")
	}
	if !bytes.Equal(envelope[:len(magic)], magic) {
		return nil, nil, nil, 0, fmt.Errorf("crypto: not a recognized encrypted file (bad magic)")
	}
	off := len(magic)
	version = int(envelope[off])
	off++
	if version != envelopeV1 && version != envelopeV2 {
		return nil, nil, nil, 0, fmt.Errorf("crypto: unsupported envelope version %d", version)
	}
	nameLen := int(envelope[off])
	off++
	if len(envelope) < off+nameLen {
		return nil, nil, nil, 0, fmt.Errorf("crypto: envelope truncated")
	}
	name := string(envelope[off : off+nameLen])
	off += nameLen
	c, err = ByName(name)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	return c, envelope[:off], envelope[off:], version, nil
}

// Open reverses Seal / SealV2, selecting the cipher and AAD construction
// recorded in the envelope. The caller passes the same aad it would give
// Seal; for a v2 envelope Open folds the header into the AEAD AAD itself.
func Open(envelope, key, aad []byte) ([]byte, error) {
	c, header, ciphertext, version, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ciphertext, key, aeadAAD(version, header, aad))
}

// ParseEnvelope validates that data has the well-formed structure Seal
// produces (magic, a supported version, and a registered cipher name)
// without decrypting it or proving authenticity. It is strict enough to
// reject "RENC"-prefixed plaintext or truncated/corrupted ciphertext,
// unlike IsEnvelope's bare magic-byte check — but it still can't prove a
// blob decrypts correctly under any particular key the way Open can.
//
// It exists for verifying wide git-history ranges (e.g. every commit
// about to be pushed), where a blob may have been sealed under a key
// that has since been rotated away and that the *current* key can no
// longer open even though it was legitimately encrypted at the time.
// Callers that have the right key on hand and need real proof of
// authenticity — such as `verify`/`status` checking HEAD, where the
// current key is expected to always work — should call Open instead.
func ParseEnvelope(data []byte) error {
	_, _, _, _, err := parseEnvelope(data)
	return err
}

// IsEnvelope reports whether data looks like a Seal-produced envelope,
// without attempting to decrypt it or even validate its structure beyond
// the magic prefix. This is a cheap check meant only for UI/status
// display (e.g. `status`'s plaintext-vs-encrypted summary); it is not
// strict enough to prove a file is actually encrypted — see ParseEnvelope
// and Open, which enforcement paths (`verify`, hooks) must use instead.
func IsEnvelope(data []byte) bool {
	return len(data) >= len(magic) && bytes.Equal(data[:len(magic)], magic)
}

// WriteFileAtomic writes data to path via a temp file in the same
// directory followed by a rename, so a crash or interrupted process never
// leaves a half-written file in place. mode is applied to the temp file
// before the rename so the final file's permissions are correct even on
// filesystems where rename doesn't preserve them.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmpPath, err := StageFileAtomic(path, data, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath) // no-op once renamed
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("crypto: rename temp file into place: %w", err)
	}
	return nil
}

// StageFileAtomic is the first half of WriteFileAtomic: it writes data to
// a temp file in the same directory as path, with mode already applied,
// and returns the temp path without renaming it into place. Callers that
// need to make writing two related files (e.g. a config and a key) look
// transactional from the outside — where a failure in step two must not
// leave step one's effect visible — stage everything first, so nothing
// touches its real path until every step that could still fail has
// already succeeded. Pair with a plain os.Rename(tmpPath, path) to
// commit, or os.Remove(tmpPath) to discard.
func StageFileAtomic(path string, data []byte, mode os.FileMode) (tmpPath string, err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return "", fmt.Errorf("crypto: create temp file: %w", err)
	}
	tmpPath = tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("crypto: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("crypto: close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("crypto: chmod temp file: %w", err)
	}
	return tmpPath, nil
}
