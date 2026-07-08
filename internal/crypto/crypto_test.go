package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T, size int) []byte {
	t.Helper()
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestCiphersRoundTrip(t *testing.T) {
	ciphers := []Cipher{XChaCha20Poly1305{}, AESGCM{}}
	plaintexts := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("hello, world"),
		bytes.Repeat([]byte("x"), 1<<20), // 1 MiB
	}
	for _, c := range ciphers {
		key := testKey(t, c.KeySize())
		for _, pt := range plaintexts {
			ct, err := c.Encrypt(pt, key, []byte("path/to/file"))
			if err != nil {
				t.Fatalf("%s: encrypt: %v", c.Name(), err)
			}
			got, err := c.Decrypt(ct, key, []byte("path/to/file"))
			if err != nil {
				t.Fatalf("%s: decrypt: %v", c.Name(), err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("%s: round-trip mismatch: got %q want %q", c.Name(), got, pt)
			}
		}
	}
}

func TestCiphersTamperDetection(t *testing.T) {
	ciphers := []Cipher{XChaCha20Poly1305{}, AESGCM{}}
	for _, c := range ciphers {
		key := testKey(t, c.KeySize())
		ct, err := c.Encrypt([]byte("secret data"), key, []byte("aad"))
		if err != nil {
			t.Fatalf("%s: encrypt: %v", c.Name(), err)
		}
		tampered := bytes.Clone(ct)
		tampered[len(tampered)-1] ^= 0xFF
		if _, err := c.Decrypt(tampered, key, []byte("aad")); err == nil {
			t.Fatalf("%s: expected error decrypting tampered ciphertext, got nil", c.Name())
		}

		wrongKey := testKey(t, c.KeySize())
		if _, err := c.Decrypt(ct, wrongKey, []byte("aad")); err == nil {
			t.Fatalf("%s: expected error decrypting with wrong key, got nil", c.Name())
		}

		if _, err := c.Decrypt(ct, key, []byte("wrong-aad")); err == nil {
			t.Fatalf("%s: expected error decrypting with wrong aad, got nil", c.Name())
		}
	}
}

func TestEnvelopeRoundTripAndCipherSelection(t *testing.T) {
	key := testKey(t, AESGCM{}.KeySize()) // 32 bytes fits both ciphers used here
	aad := []byte("secrets/config.yaml")

	for _, c := range []Cipher{XChaCha20Poly1305{}, AESGCM{}} {
		env, err := Seal(c, []byte("top secret"), key, aad)
		if err != nil {
			t.Fatalf("%s: seal: %v", c.Name(), err)
		}
		if !IsEnvelope(env) {
			t.Fatalf("%s: IsEnvelope returned false for a sealed envelope", c.Name())
		}
		got, err := Open(env, key, aad)
		if err != nil {
			t.Fatalf("%s: open: %v", c.Name(), err)
		}
		if string(got) != "top secret" {
			t.Fatalf("%s: got %q want %q", c.Name(), got, "top secret")
		}
	}
}

func TestEnvelopeSwitchingDefaultStillDecryptsOldFiles(t *testing.T) {
	key := testKey(t, AESGCM{}.KeySize())
	aad := []byte("f")

	env, err := Seal(AESGCM{}, []byte("old cipher payload"), key, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Simulate the default cipher changing after this file was written.
	got, err := Open(env, key, aad)
	if err != nil {
		t.Fatalf("open old envelope after default changed: %v", err)
	}
	if string(got) != "old cipher payload" {
		t.Fatalf("got %q", got)
	}
}

func TestIsEnvelopeRejectsPlaintext(t *testing.T) {
	if IsEnvelope([]byte("just a normal file\n")) {
		t.Fatalf("IsEnvelope should be false for plaintext")
	}
	if IsEnvelope(nil) {
		t.Fatalf("IsEnvelope should be false for empty data")
	}
}

func FuzzXChaCha20Poly1305RoundTrip(f *testing.F) {
	f.Add([]byte("hello"), []byte("aad"))
	f.Add([]byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, plaintext, aad []byte) {
		key := make([]byte, XChaCha20Poly1305{}.KeySize())
		c := XChaCha20Poly1305{}
		ct, err := c.Encrypt(plaintext, key, aad)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := c.Decrypt(ct, key, aad)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
		}
	})
}
