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

func TestEnvelopeV2RoundTripAndVersion(t *testing.T) {
	for _, c := range []Cipher{XChaCha20Poly1305{}, AESGCM{}} {
		key := testKey(t, c.KeySize())
		aad := []byte("repo-abc\x1fsecrets/db.yaml")

		env, err := SealV2(c, []byte("top secret"), key, aad)
		if err != nil {
			t.Fatalf("%s SealV2: %v", c.Name(), err)
		}
		if v, err := Version(env); err != nil || v != 2 {
			t.Fatalf("%s: Version = %d, %v; want 2", c.Name(), v, err)
		}
		got, err := Open(env, key, aad)
		if err != nil || string(got) != "top secret" {
			t.Fatalf("%s Open(v2): got %q err %v", c.Name(), got, err)
		}
		// A different AAD (different repo id) must not authenticate.
		if _, err := Open(env, key, []byte("repo-XXX\x1fsecrets/db.yaml")); err == nil {
			t.Fatalf("%s: v2 envelope opened under a different AAD", c.Name())
		}
	}
}

func TestEnvelopeV2AuthenticatesHeader(t *testing.T) {
	key := testKey(t, XChaCha20Poly1305{}.KeySize())
	aad := []byte("repo-abc\x1fx")
	env, err := SealV2(XChaCha20Poly1305{}, []byte("payload"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the header (the cipher-name length). v1 would
	// surface this only as a downstream parse/opaque failure; v2 rejects
	// it as an authentication failure.
	tampered := append([]byte(nil), env...)
	tampered[len(magic)+2] ^= 0x01
	if _, err := Open(tampered, key, aad); err == nil {
		t.Fatal("v2 envelope opened after its header was tampered")
	}

	// Version downgrade 2 -> 1: parseEnvelope now treats it as v1 (AAD =
	// caller aad only), but the ciphertext was sealed with header||aad, so
	// authentication fails.
	downgraded := append([]byte(nil), env...)
	downgraded[len(magic)] = envelopeV1
	if _, err := Open(downgraded, key, aad); err == nil {
		t.Fatal("v2 envelope opened after being downgraded to v1 in the header")
	}
}

func TestEnvelopeV1UnaffectedByV2(t *testing.T) {
	// A v1 blob sealed before this change (path-only AAD, header outside
	// the AEAD) must still open with the identical call.
	key := testKey(t, XChaCha20Poly1305{}.KeySize())
	aad := []byte("secrets/db.yaml")
	env, err := Seal(XChaCha20Poly1305{}, []byte("legacy payload"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := Version(env); v != 1 {
		t.Fatalf("Seal wrote version %d, want 1", v)
	}
	got, err := Open(env, key, aad)
	if err != nil || string(got) != "legacy payload" {
		t.Fatalf("v1 Open: got %q err %v", got, err)
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
