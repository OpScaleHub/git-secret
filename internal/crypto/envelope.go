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

const envelopeVersion = 1

// Seal encrypts plaintext with c and wraps it in a self-describing envelope
// (magic + version + cipher name + ciphertext) so Open can later pick the
// correct cipher even if Default has changed. aad is typically the file's
// repo-relative path, which binds ciphertext to its location and blocks
// swapping encrypted blobs between files.
func Seal(c Cipher, plaintext, key, aad []byte) ([]byte, error) {
	ciphertext, err := c.Encrypt(plaintext, key, aad)
	if err != nil {
		return nil, err
	}
	name := []byte(c.Name())
	if len(name) > 255 {
		return nil, fmt.Errorf("crypto: cipher name too long: %s", c.Name())
	}
	buf := bytes.NewBuffer(nil)
	buf.Write(magic)
	buf.WriteByte(envelopeVersion)
	buf.WriteByte(byte(len(name)))
	buf.Write(name)
	buf.Write(ciphertext)
	return buf.Bytes(), nil
}

// Open reverses Seal, selecting the cipher recorded in the envelope.
func Open(envelope, key, aad []byte) ([]byte, error) {
	if len(envelope) < len(magic)+2 {
		return nil, fmt.Errorf("crypto: envelope too short")
	}
	if !bytes.Equal(envelope[:len(magic)], magic) {
		return nil, fmt.Errorf("crypto: not a recognized encrypted file (bad magic)")
	}
	off := len(magic)
	version := envelope[off]
	off++
	if version != envelopeVersion {
		return nil, fmt.Errorf("crypto: unsupported envelope version %d", version)
	}
	nameLen := int(envelope[off])
	off++
	if len(envelope) < off+nameLen {
		return nil, fmt.Errorf("crypto: envelope truncated")
	}
	name := string(envelope[off : off+nameLen])
	off += nameLen
	c, err := ByName(name)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(envelope[off:], key, aad)
}

// IsEnvelope reports whether data looks like a Seal-produced envelope,
// without attempting to decrypt it. Used by `verify` and `status`.
func IsEnvelope(data []byte) bool {
	return len(data) >= len(magic) && bytes.Equal(data[:len(magic)], magic)
}

// WriteFileAtomic writes data to path via a temp file in the same
// directory followed by a rename, so a crash or interrupted process never
// leaves a half-written file in place. mode is applied to the temp file
// before the rename so the final file's permissions are correct even on
// filesystems where rename doesn't preserve them.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("crypto: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("crypto: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("crypto: close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("crypto: chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("crypto: rename temp file into place: %w", err)
	}
	return nil
}
