package sealer

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// shortTempDir returns a temp dir short enough for gpg-agent's Unix
// domain socket path (macOS's default TMPDIR, /var/folders/.../T/..., is
// long enough to blow past the ~104 byte sockaddr_un limit and make
// gpg-agent fail to bind at all -- not a sealer bug, a CI-environment
// quirk internal/gpgutil's own tests already work around the same way).
func shortTempDir(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "sealer-test-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// skipUnlessGPGTestable skips on environments where real gpg operations
// can't be exercised reliably: gpg missing, or GitHub's windows-latest
// runners, where gpg-agent is unreliably reachable for unattended key
// generation -- mirrors internal/gpgutil's own skipUnlessGPGTestable.
func skipUnlessGPGTestable(t *testing.T) {
	t.Helper()
	if !gpgutil.Available() {
		t.Skip("gpg not installed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("gpg-agent unreliable on windows CI runners")
	}
}

// genTestKey creates a throwaway, unattended (no passphrase, no expiry)
// GPG identity in gnupgHome (never the caller's real keyring) and returns
// its fingerprint. Callers should create gnupgHome via shortTempDir, not
// t.TempDir() directly -- see its doc comment for why.
func genTestKey(t *testing.T, gnupgHome string) string {
	t.Helper()
	skipUnlessGPGTestable(t)

	cmd := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-generate-key", "sealer test <sealer-test@example.invalid>", "default", "default", "never")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Not necessarily this environment's fault (gpg-agent flakiness
		// has recurred in sandboxed/CI environments even with a valid
		// key/setup) -- skip rather than fail the whole suite on it.
		t.Skipf("gpg key generation not usable in this environment, skipping: %v: %s", err, out)
	}

	cmd = exec.Command("gpg", "--batch", "--with-colons", "--list-secret-keys")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	out, err := cmd.Output()
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
	gnupgHome := shortTempDir(t)
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
	gnupgHome := shortTempDir(t)
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
	homeA := shortTempDir(t)
	fprA := genTestKey(t, homeA)

	t.Setenv("GNUPGHOME", homeA)
	spec, err := Seal("downtime", "downtime-secrets", map[string]string{"K": "v"}, []string{fprA})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	originalEncryptedData := spec.EncryptedData["K"]

	homeB := shortTempDir(t)
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
	gnupgHome := shortTempDir(t)
	t.Setenv("GNUPGHOME", gnupgHome)
	if !gpgutil.Available() {
		t.Skip("gpg binary not on PATH")
	}

	_, err := Seal("ns", "name", map[string]string{"K": "v"}, []string{"DEADBEEF"})
	if err == nil {
		t.Fatal("Seal accepted a short key ID instead of requiring a full fingerprint")
	}
}
