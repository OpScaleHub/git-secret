package keybackend

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileBackendGenerateThenGet(t *testing.T) {
	repoRoot := t.TempDir()
	b := FileBackend{}

	if _, err := b.Get(repoRoot, ".repo-enc/key"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get before Generate: got %v, want ErrKeyNotFound", err)
	}

	key, err := b.Generate(repoRoot, ".repo-enc/key")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("Generate: len = %d, want %d", len(key), KeySize)
	}

	got, err := b.Get(repoRoot, ".repo-enc/key")
	if err != nil {
		t.Fatalf("Get after Generate: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("Get returned %x, want %x", got, key)
	}

	// Key file must not be world/group readable. Windows has no concept
	// of Unix permission bits (os.Chmod there only toggles a read-only
	// attribute, always reporting 0666/0777) so this check is meaningless
	// there; real access control on Windows would need ACL syscalls,
	// out of scope for a minimal-dependency CLI.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(repoRoot, ".repo-enc/key"))
		if err != nil {
			t.Fatalf("stat key file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("key file mode = %o, want 0600", perm)
		}
	}
}

func TestFileBackendGenerateOverwritesExisting(t *testing.T) {
	repoRoot := t.TempDir()
	b := FileBackend{}

	first, err := b.Generate(repoRoot, ".repo-enc/key")
	if err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	second, err := b.Generate(repoRoot, ".repo-enc/key")
	if err != nil {
		t.Fatalf("second Generate: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatalf("expected Generate to produce a different key each call")
	}
}

func TestFileBackendRejectsCorruptKey(t *testing.T) {
	repoRoot := t.TempDir()
	keyPath := filepath.Join(repoRoot, ".repo-enc", "key")
	os.MkdirAll(filepath.Dir(keyPath), 0o700)
	os.WriteFile(keyPath, []byte("not-hex-and-wrong-length\n"), 0o600)

	if _, err := (FileBackend{}).Get(repoRoot, ".repo-enc/key"); err == nil {
		t.Fatalf("expected error reading corrupt key file")
	}
}

func TestEnvBackendGetMissingAndSet(t *testing.T) {
	b := EnvBackend{}
	const varName = "REPO_ENC_TEST_KEY"
	os.Unsetenv(varName)

	if _, err := b.Get("", varName); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get with unset var: got %v, want ErrKeyNotFound", err)
	}

	key, err := b.Generate("", varName)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("Generate: len = %d, want %d", len(key), KeySize)
	}

	t.Setenv(varName, hex.EncodeToString(key))
	got, err := b.Get("", varName)
	if err != nil {
		t.Fatalf("Get after setting env: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("Get returned %x, want %x", got, key)
	}
}

func TestEnvBackendRejectsBadValue(t *testing.T) {
	const varName = "REPO_ENC_TEST_BAD_KEY"
	t.Setenv(varName, "not-hex")
	if _, err := (EnvBackend{}).Get("", varName); err == nil {
		t.Fatalf("expected error for non-hex env value")
	}

	t.Setenv(varName, hex.EncodeToString([]byte("short")))
	if _, err := (EnvBackend{}).Get("", varName); err == nil {
		t.Fatalf("expected error for wrong-length key")
	}
}

func TestNewUnknownBackend(t *testing.T) {
	if _, err := New("bogus"); err == nil {
		t.Fatalf("expected error for unknown backend")
	}
	if _, err := New("file"); err != nil {
		t.Fatalf("New(file): %v", err)
	}
	if _, err := New("env"); err != nil {
		t.Fatalf("New(env): %v", err)
	}
}
