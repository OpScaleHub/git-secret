package gpgutil

import (
	"bytes"
	"os/exec"
	"runtime"
	"testing"
)

// skipUnlessGPGTestable skips on environments where real gpg operations
// can't be exercised reliably: gpg missing, or GitHub's windows-latest
// runners, where gpg-agent is unreliably reachable for unattended key
// generation (a CI environment quirk, not a limitation of the feature
// itself — this is exercised manually on real Windows installs).
func skipUnlessGPGTestable(t *testing.T) {
	t.Helper()
	if !Available() {
		t.Skip("gpg not installed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("gpg-agent unreliable on windows CI runners")
	}
}

// newTestKeyring generates an ephemeral, unattended (no passphrase, no
// expiry) GPG identity in a throwaway GNUPGHOME, so tests never touch
// the developer's real keyring. Returns the primary key's fingerprint.
func newTestKeyring(t *testing.T, uid string) string {
	t.Helper()
	skipUnlessGPGTestable(t)
	home := t.TempDir()
	t.Setenv("GNUPGHOME", home)

	cmd := exec.Command(Binary, "--batch", "--passphrase", "", "--quick-generate-key", uid, "default", "default", "never")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("generate test key: %v: %s", err, stderr.String())
	}

	keys, err := ListSecretKeys()
	if err != nil {
		t.Fatalf("ListSecretKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected exactly 1 secret key, got %d", len(keys))
	}
	return keys[0].Fingerprint
}

func TestListSecretKeysAgainstRealKeyring(t *testing.T) {
	fpr := newTestKeyring(t, "Test User <test@example.com>")
	if len(fpr) != 40 {
		t.Fatalf("fingerprint length = %d, want 40 (hex): %q", len(fpr), fpr)
	}

	keys, err := ListSecretKeys()
	if err != nil {
		t.Fatalf("ListSecretKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Fingerprint != fpr {
		t.Fatalf("ListSecretKeys = %+v, want fingerprint %s", keys, fpr)
	}
	if len(keys[0].UserIDs) != 1 || keys[0].UserIDs[0] != "Test User <test@example.com>" {
		t.Fatalf("UserIDs = %v, want [\"Test User <test@example.com>\"]", keys[0].UserIDs)
	}
}

func TestListPublicKeysAgainstRealKeyring(t *testing.T) {
	fpr := newTestKeyring(t, "Pub Test <pub@example.com>")

	keys, err := ListPublicKeys("")
	if err != nil {
		t.Fatalf("ListPublicKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Fingerprint != fpr {
		t.Fatalf("ListPublicKeys = %+v, want fingerprint %s", keys, fpr)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	fpr := newTestKeyring(t, "Roundtrip <roundtrip@example.com>")

	plaintext := []byte("a 32 byte data encryption key!!")
	wrapped, err := Encrypt(plaintext, []string{fpr})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Contains(wrapped, []byte("BEGIN PGP MESSAGE")) {
		t.Fatalf("Encrypt output doesn't look armored: %q", wrapped)
	}

	got, err := Decrypt(wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt = %q, want %q", got, plaintext)
	}
}

func TestEncryptRequiresRecipients(t *testing.T) {
	if _, err := Encrypt([]byte("x"), nil); err == nil {
		t.Fatalf("expected error encrypting with no recipients")
	}
}

func TestDecryptRejectsGarbage(t *testing.T) {
	skipUnlessGPGTestable(t)
	t.Setenv("GNUPGHOME", t.TempDir())
	if _, err := Decrypt([]byte("not a pgp message")); err == nil {
		t.Fatalf("expected error decrypting garbage input")
	}
}

// TestParseColonKeysPinnedFormat pins the parser against real
// --with-colons output captured from a live gpg 2.4.8 session (including
// a signing primary key plus an encryption subkey, which is the default
// gpg --quick-generate-key shape) so the parsing logic stays
// regression-proof even if the local gpg version later drifts.
func TestParseColonKeysPinnedFormat(t *testing.T) {
	const secretOutput = `sec:u:255:22:5749E27662994D10:1783545379:::u:::scESC:::+::ed25519:::0:
fpr:::::::::438DB5CA6E3E8FCBA29006055749E27662994D10:
grp:::::::::87CDA8D3B073788052F8F61739A4C51266ED7EA7:
uid:u::::1783545379::F2E723F89EE13F7007A48DDACDB395768100ABC3::Test User <test@example.com>::::::::::0:
ssb:u:255:18:4128D1B3B49CFBAD:1783545379::::::e:::+::cv25519::
fpr:::::::::29CC684D146E3D162FE424CC4128D1B3B49CFBAD:
grp:::::::::1C505496B0C471521A0B259606C6C4678C0573AD:
`
	keys := parseColonKeys([]byte(secretOutput), "sec")
	if len(keys) != 1 {
		t.Fatalf("parsed %d keys, want 1", len(keys))
	}
	k := keys[0]
	if k.Fingerprint != "438DB5CA6E3E8FCBA29006055749E27662994D10" {
		t.Fatalf("Fingerprint = %q, want the PRIMARY key's fpr (not the ssb subkey's)", k.Fingerprint)
	}
	if len(k.UserIDs) != 1 || k.UserIDs[0] != "Test User <test@example.com>" {
		t.Fatalf("UserIDs = %v", k.UserIDs)
	}
}

func TestParseColonKeysMultipleKeys(t *testing.T) {
	const output = `sec:u:255:22:AAAA:1000:::u:::scESC:::+::ed25519:::0:
fpr:::::::::1111111111111111111111111111111111111111:
uid:u::::1000::x::First Key <a@example.com>::::::::::0:
sec:u:255:22:BBBB:2000:::u:::scESC:::+::ed25519:::0:
fpr:::::::::2222222222222222222222222222222222222222:
uid:u::::2000::x::Second Key <b@example.com>::::::::::0:
`
	keys := parseColonKeys([]byte(output), "sec")
	if len(keys) != 2 {
		t.Fatalf("parsed %d keys, want 2", len(keys))
	}
	if keys[0].Fingerprint != "1111111111111111111111111111111111111111" || keys[1].Fingerprint != "2222222222222222222222222222222222222222" {
		t.Fatalf("fingerprints = %q, %q", keys[0].Fingerprint, keys[1].Fingerprint)
	}
}
