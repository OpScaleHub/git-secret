package keybackend

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// newTestGPGIdentity generates an ephemeral, unattended GPG identity in
// a throwaway GNUPGHOME (never the developer's real keyring) and returns
// its primary key fingerprint.
func newTestGPGIdentity(t *testing.T, uid string) string {
	t.Helper()
	if !gpgutil.Available() {
		t.Skip("gpg not installed")
	}
	if runtime.GOOS == "windows" {
		// gpg-agent is unreliably reachable on GitHub's windows-latest
		// runners for unattended key generation — a CI environment
		// quirk, not a limitation of the feature itself.
		t.Skip("gpg-agent unreliable on windows CI runners")
	}
	t.Setenv("GNUPGHOME", t.TempDir())

	cmd := exec.Command(gpgutil.Binary, "--batch", "--passphrase", "", "--quick-generate-key", uid, "default", "default", "never")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("generate test key: %v: %s", err, stderr.String())
	}
	keys, err := gpgutil.ListSecretKeys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListSecretKeys: keys=%v err=%v", keys, err)
	}
	return keys[0].Fingerprint
}

func TestGPGBackendGenerateThenGet(t *testing.T) {
	fpr := newTestGPGIdentity(t, "Test <test@example.com>")
	repoRoot := t.TempDir()
	b := GPGBackend{}.WithRecipients([]string{fpr})

	if _, err := b.Get(repoRoot, ".repo-enc/key.gpg"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get before Generate: got %v, want ErrKeyNotFound", err)
	}

	key, err := b.Generate(repoRoot, ".repo-enc/key.gpg")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("Generate: len = %d, want %d", len(key), KeySize)
	}

	got, err := b.Get(repoRoot, ".repo-enc/key.gpg")
	if err != nil {
		t.Fatalf("Get after Generate: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("Get returned %x, want %x", got, key)
	}

	// Unlike the file backend, this blob is meant to be committed:
	// normal permissions, not locked-down 0600/0700.
	info, err := os.Stat(filepath.Join(repoRoot, ".repo-enc/key.gpg"))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o044 == 0 {
		t.Errorf("key file mode = %o, want group/other readable (it's meant to be committed)", perm)
	}
}

func TestGPGBackendGenerateRequiresRecipients(t *testing.T) {
	if !gpgutil.Available() {
		t.Skip("gpg not installed")
	}
	repoRoot := t.TempDir()
	if _, err := (GPGBackend{}).Generate(repoRoot, ".repo-enc/key.gpg"); err == nil {
		t.Fatalf("expected error generating with no recipients")
	}
}

func TestGPGBackendGetRejectsCorruptBlob(t *testing.T) {
	fpr := newTestGPGIdentity(t, "Test <test@example.com>")
	repoRoot := t.TempDir()
	keyPath := filepath.Join(repoRoot, ".repo-enc", "key.gpg")
	os.MkdirAll(filepath.Dir(keyPath), 0o755)
	os.WriteFile(keyPath, []byte("not a pgp message"), 0o644)

	b := GPGBackend{}.WithRecipients([]string{fpr})
	if _, err := b.Get(repoRoot, ".repo-enc/key.gpg"); err == nil {
		t.Fatalf("expected error reading corrupt gpg blob")
	}
}

func TestGPGBackendGetNoMatchingSecretKeyMapsToErrKeyNotFound(t *testing.T) {
	// Wrap under identity A, then try to Get from a keyring that only
	// has identity B's secret key (simulating a stranger who cloned the
	// repo but was never added as a recipient).
	fprA := newTestGPGIdentity(t, "A <a@example.com>")
	repoRoot := t.TempDir()
	b := GPGBackend{}.WithRecipients([]string{fprA})
	if _, err := b.Generate(repoRoot, ".repo-enc/key.gpg"); err != nil {
		t.Fatalf("Generate under identity A: %v", err)
	}

	newTestGPGIdentity(t, "B <b@example.com>") // switches GNUPGHOME to a keyring without A's secret key

	if _, err := b.Get(repoRoot, ".repo-enc/key.gpg"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get with no matching secret key: got %v, want ErrKeyNotFound", err)
	}
}
