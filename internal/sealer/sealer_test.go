package sealer

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// genTestKey creates a throwaway GPG identity in an isolated GNUPGHOME
// (never the caller's real keyring) and returns its fingerprint. Mirrors
// the isolation cmd/git-secret-server's own tests and startup use.
func genTestKey(t *testing.T, gnupgHome string) string {
	t.Helper()
	if !gpgutil.Available() {
		t.Skip("gpg binary not on PATH")
	}
	batch := `
Key-Type: EDDSA
Key-Curve: ed25519
Subkey-Type: ECDH
Subkey-Curve: cv25519
Name-Real: sealer test
Name-Email: sealer-test@example.invalid
Expire-Date: 0
%no-protection
%commit
`
	cmd := exec.Command("gpg", "--batch", "--gen-key")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	cmd.Stdin = strings.NewReader(batch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gpg --gen-key: %v\n%s", err, out)
	}

	cmd = exec.Command("gpg", "--batch", "--with-colons", "--list-secret-keys")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	out, err = cmd.Output()
	if err != nil {
		t.Fatalf("list-secret-keys: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			f := strings.Split(line, ":")
			if len(f) > 9 {
				return f[9]
			}
		}
	}
	t.Fatal("no fingerprint found after gen-key")
	return ""
}

func exportPublicKey(t *testing.T, gnupgHome, fpr string) []byte {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--armor", "--export", fpr)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("export public key: %v", err)
	}
	return out
}

func importPublicKey(t *testing.T, gnupgHome string, armored []byte) {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--import")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	cmd.Stdin = strings.NewReader(string(armored))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("import public key: %v\n%s", err, out)
	}
}

func TestSealUnsealRoundTrip(t *testing.T) {
	gnupgHome := t.TempDir()
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		t.Fatal(err)
	}
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	data := map[string]string{
		"USERNAME": "admin",
		"PASSWORD": "correct horse battery staple",
	}

	spec, err := Seal("downtime", "downtime-secrets", data, []string{fpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if spec.EncryptedKey == "" {
		t.Fatal("EncryptedKey empty")
	}
	if len(spec.EncryptedData) != len(data) {
		t.Fatalf("EncryptedData has %d entries, want %d", len(spec.EncryptedData), len(data))
	}
	for k, v := range spec.EncryptedData {
		if strings.Contains(v, "PASSWORD") || strings.Contains(v, data[k]) {
			t.Fatalf("ciphertext for %q looks like it contains plaintext", k)
		}
	}

	got, err := Unseal("downtime", "downtime-secrets", spec)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("Unseal returned %d entries, want %d", len(got), len(data))
	}
	for k, want := range data {
		if got[k] != want {
			t.Errorf("key %q: got %q, want %q", k, got[k], want)
		}
	}
}

// TestUnsealWrongObjectFails proves the namespace/name/key AAD binding is
// load-bearing: an entry sealed for one GitSecret must not decrypt when
// presented as belonging to a different one, even with the right key.
func TestUnsealWrongObjectFails(t *testing.T) {
	gnupgHome := t.TempDir()
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		t.Fatal(err)
	}
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	spec, err := Seal("downtime", "downtime-secrets", map[string]string{"K": "v"}, []string{fpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := Unseal("downtime", "some-other-secret", spec); err == nil {
		t.Fatal("Unseal succeeded against a different object name; AAD binding is not working")
	}
	if _, err := Unseal("other-namespace", "downtime-secrets", spec); err == nil {
		t.Fatal("Unseal succeeded against a different namespace; AAD binding is not working")
	}

	// Sanity: the original namespace/name still works.
	if _, err := Unseal("downtime", "downtime-secrets", spec); err != nil {
		t.Fatalf("Unseal with the correct namespace/name failed: %v", err)
	}
}

// TestRewrap_AddsRecipientWithoutTouchingEncryptedData is the core proof
// behind git-secret#34's argument for a native CRD over copying sealed-
// secrets' design outright: adding a second recipient must be a small,
// cheap operation on EncryptedKey alone, and the new recipient must be
// able to decrypt independently afterward -- without recipient A's key
// present at all.
func TestRewrap_AddsRecipientWithoutTouchingEncryptedData(t *testing.T) {
	homeA := t.TempDir()
	if err := os.Chmod(homeA, 0o700); err != nil {
		t.Fatal(err)
	}
	fprA := genTestKey(t, homeA)

	t.Setenv("GNUPGHOME", homeA)
	spec, err := Seal("downtime", "downtime-secrets", map[string]string{"K": "v"}, []string{fprA})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	originalEncryptedData := spec.EncryptedData["K"]

	homeB := t.TempDir()
	if err := os.Chmod(homeB, 0o700); err != nil {
		t.Fatal(err)
	}
	fprB := genTestKey(t, homeB)

	// Rewrapping to B requires B's PUBLIC key in A's keyring first --
	// same precondition git-secret's existing `adduser` command already
	// has for whole-repo files (see keybackend.GPGBackend/gpgutil docs):
	// you can encrypt to someone whose public key you hold, whether or
	// not you can decrypt anything they've sent you.
	pub := exportPublicKey(t, homeB, fprB)
	importPublicKey(t, homeA, pub)

	// Rewrap runs with A's keyring present (A is a current recipient),
	// adding B to the list.
	t.Setenv("GNUPGHOME", homeA)
	rewrapped, err := Rewrap(spec, []string{fprA, fprB})
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	if rewrapped.EncryptedData["K"] != originalEncryptedData {
		t.Fatal("Rewrap touched EncryptedData -- it must only replace EncryptedKey")
	}
	if rewrapped.EncryptedKey == spec.EncryptedKey {
		t.Fatal("Rewrap did not actually change EncryptedKey")
	}

	// The original recipient can still decrypt (rewrap didn't lock A out).
	t.Setenv("GNUPGHOME", homeA)
	if got, err := Unseal("downtime", "downtime-secrets", rewrapped); err != nil || got["K"] != "v" {
		t.Fatalf("recipient A can no longer decrypt after rewrap: got=%v err=%v", got, err)
	}

	// B, who was never involved in the original Seal call and holds no
	// key related to it beyond what Rewrap just wrapped to, can now
	// independently decrypt -- proving this isn't a single-keypair design.
	t.Setenv("GNUPGHOME", homeB)
	got, err := Unseal("downtime", "downtime-secrets", rewrapped)
	if err != nil {
		t.Fatalf("recipient B cannot decrypt after being added via Rewrap: %v", err)
	}
	if got["K"] != "v" {
		t.Fatalf("recipient B decrypted wrong value: %q", got["K"])
	}
}

func TestSealRejectsShortRecipientID(t *testing.T) {
	gnupgHome := t.TempDir()
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupgHome)
	if !gpgutil.Available() {
		t.Skip("gpg binary not on PATH")
	}

	_, err := Seal("ns", "name", map[string]string{"K": "v"}, []string{"DEADBEEF"})
	if err == nil {
		t.Fatal("Seal accepted a short key ID instead of requiring a full fingerprint")
	}
}
