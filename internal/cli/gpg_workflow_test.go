package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/gpgutil"
	"github.com/OpScaleHub/git-secret/keybackend"
)

// shortTempDir returns a short-path temp directory suitable for
// GNUPGHOME. t.TempDir() on macOS lives under a long
// /var/folders/.../T/<test name>/001 path, and gpg-agent's Unix domain
// socket (created inside GNUPGHOME) can exceed AF_UNIX's ~104-byte
// sun_path limit there ("File name too long" / "IPC connect call
// failed") — a real GnuPG-on-macOS gotcha, unrelated to this feature.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gnupg-test-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// gpgIdentity is a throwaway GPG identity generated in its own isolated
// GNUPGHOME, so tests can simulate multiple separate people without ever
// touching the developer's real keyring.
type gpgIdentity struct {
	home        string
	fingerprint string
}

func newGPGIdentity(t *testing.T, uid string) gpgIdentity {
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
	home := shortTempDir(t)
	withGNUPGHome(t, home)

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
	return gpgIdentity{home: home, fingerprint: keys[0].Fingerprint}
}

// withGNUPGHome sets GNUPGHOME for the remainder of the current test.
// gpgutil always operates against whatever GNUPGHOME is currently set,
// so "switching identity" in these tests just means calling this again.
func withGNUPGHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("GNUPGHOME", home)
}

func exportKey(t *testing.T, home, fingerprint string, secret bool) []byte {
	t.Helper()
	arg := "--export"
	if secret {
		arg = "--export-secret-keys"
	}
	cmd := exec.Command(gpgutil.Binary, "--batch", "--armor", arg, fingerprint)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("export key: %v: %s", err, stderr.String())
	}
	return stdout.Bytes()
}

func importKey(t *testing.T, home string, armored []byte) {
	t.Helper()
	cmd := exec.Command(gpgutil.Binary, "--batch", "--import")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	cmd.Stdin = bytes.NewReader(armored)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("import key: %v: %s", err, stderr.String())
	}
}

// newSharedKeyring builds a keyring containing identity a's secret+public
// key and identity b's public key only — exactly what "person A, who also
// knows about B's public key" would have. It does NOT contain B's secret
// key, so it cannot decrypt anything only wrapped for B.
func newSharedKeyring(t *testing.T, a, b gpgIdentity) string {
	t.Helper()
	pubA := exportKey(t, a.home, a.fingerprint, false)
	secA := exportKey(t, a.home, a.fingerprint, true)
	pubB := exportKey(t, b.home, b.fingerprint, false)

	shared := shortTempDir(t)
	importKey(t, shared, pubA)
	importKey(t, shared, secA)
	importKey(t, shared, pubB)
	return shared
}

func TestInitWithGPGBackend(t *testing.T) {
	a := newGPGIdentity(t, "A <a@example.com>")
	root := newTestRepo(t)
	withGNUPGHome(t, a.home)

	result, err := Init(InitOptions{Patterns: []string{"secrets/**"}, KeyBackend: "gpg", GPGRecipients: []string{a.fingerprint}})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !result.GeneratedKey {
		t.Fatalf("expected Init to generate a key on first run")
	}
	if !result.KeyIsCommittable {
		t.Fatalf("expected KeyIsCommittable for gpg backend")
	}

	// Unlike the file backend, the wrapped key must NOT be gitignored.
	gitignore, _ := os.ReadFile(filepath.Join(root, ".gitignore"))
	if bytes.Contains(gitignore, []byte(".repo-enc/key.gpg")) {
		t.Fatalf(".gitignore should not cover the gpg-wrapped key file: %q", gitignore)
	}

	cfgData, _ := os.ReadFile(result.ConfigPath)
	if !bytes.Contains(cfgData, []byte(a.fingerprint)) {
		t.Fatalf("config does not contain the recipient fingerprint: %s", cfgData)
	}

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	key, err := ctx.Key()
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if len(key) != keybackend.KeySize {
		t.Fatalf("Key length = %d, want %d", len(key), keybackend.KeySize)
	}
}

func TestRotateKeysGPGBackend(t *testing.T) {
	a := newGPGIdentity(t, "A <a@example.com>")
	root := newTestRepo(t)
	withGNUPGHome(t, a.home)

	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}, KeyBackend: "gpg", GPGRecipients: []string{a.fingerprint}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	before, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))

	result, err := ctx.RotateKeys()
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if len(result.RotatedFiles) != 1 {
		t.Fatalf("RotatedFiles = %v, want 1", result.RotatedFiles)
	}
	after, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if bytes.Equal(before, after) {
		t.Fatalf("ciphertext unchanged after rotation")
	}

	touched, err := ctx.Unlock()
	if err != nil {
		t.Fatalf("Unlock after rotate: %v", err)
	}
	if len(touched) != 1 {
		t.Fatalf("Unlock touched = %v", touched)
	}
	data, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if string(data) != "password: hunter2\n" {
		t.Fatalf("data incorrect after rotation+unlock: %q", data)
	}
}

func TestAddUserRewrapsWithoutReencrypting(t *testing.T) {
	a := newGPGIdentity(t, "A <a@example.com>")
	b := newGPGIdentity(t, "B <b@example.com>")
	shared := newSharedKeyring(t, a, b)

	root := newTestRepo(t)
	withGNUPGHome(t, shared)

	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}, KeyBackend: "gpg", GPGRecipients: []string{a.fingerprint}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	fileBefore, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))

	result, err := ctx.AddUser(b.fingerprint)
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if result.AlreadyPresent {
		t.Fatalf("expected AlreadyPresent=false for a brand new recipient")
	}

	// The DEK didn't change, so the file's ciphertext must be byte-for-byte
	// identical -- only the small key blob should have been touched.
	fileAfter, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if !bytes.Equal(fileBefore, fileAfter) {
		t.Fatalf("AddUser should not re-encrypt files: before=%x after=%x", fileBefore, fileAfter)
	}

	if len(ctx.Config.GPGRecipients) != 2 {
		t.Fatalf("GPGRecipients = %v, want 2 entries", ctx.Config.GPGRecipients)
	}

	// Adding the same recipient again is a harmless no-op.
	again, err := ctx.AddUser(b.fingerprint)
	if err != nil {
		t.Fatalf("AddUser (again): %v", err)
	}
	if !again.AlreadyPresent {
		t.Fatalf("expected AlreadyPresent=true re-adding an existing recipient")
	}

	// B, on their own machine (their own keyring, no relation to `shared`),
	// must now be able to decrypt the repo's key using only their own
	// already-present secret key.
	withGNUPGHome(t, b.home)
	bBackend, err := resolveBackend(ctx.Config)
	if err != nil {
		t.Fatalf("resolveBackend: %v", err)
	}
	if _, err := bBackend.Get(root, ctx.Config.KeySource); err != nil {
		t.Fatalf("B should be able to decrypt after AddUser: %v", err)
	}
}

func TestRemoveUserForcesRotationAndRevokesAccess(t *testing.T) {
	a := newGPGIdentity(t, "A <a@example.com>")
	b := newGPGIdentity(t, "B <b@example.com>")
	shared := newSharedKeyring(t, a, b)

	root := newTestRepo(t)
	withGNUPGHome(t, shared)

	if _, err := Init(InitOptions{
		Patterns: []string{"secrets/**"}, KeyBackend: "gpg",
		GPGRecipients: []string{a.fingerprint, b.fingerprint},
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "secrets/db.yaml", "password: hunter2\n")

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	// Confirm B can decrypt BEFORE removal.
	withGNUPGHome(t, b.home)
	bBackendBefore, err := resolveBackend(ctx.Config)
	if err != nil {
		t.Fatalf("resolveBackend: %v", err)
	}
	if _, err := bBackendBefore.Get(root, ctx.Config.KeySource); err != nil {
		t.Fatalf("B should be able to decrypt before removal: %v", err)
	}

	fileBefore, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))

	withGNUPGHome(t, shared)
	result, err := ctx.RemoveUser(b.fingerprint)
	if err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if len(result.RotateResult.RotatedFiles) != 1 {
		t.Fatalf("RotatedFiles = %v, want 1 (removeuser must re-encrypt)", result.RotateResult.RotatedFiles)
	}
	fileAfter, _ := os.ReadFile(filepath.Join(root, "secrets/db.yaml"))
	if bytes.Equal(fileBefore, fileAfter) {
		t.Fatalf("removeuser must rotate the DEK, but ciphertext is unchanged")
	}
	if len(ctx.Config.GPGRecipients) != 1 || ctx.Config.GPGRecipients[0] != a.fingerprint {
		t.Fatalf("GPGRecipients after removal = %v, want [%s]", ctx.Config.GPGRecipients, a.fingerprint)
	}

	// B must no longer be able to decrypt at all -- their old secret key
	// still exists, but the new key was never wrapped for them.
	withGNUPGHome(t, b.home)
	bBackendAfter, err := resolveBackend(ctx.Config)
	if err != nil {
		t.Fatalf("resolveBackend: %v", err)
	}
	if _, err := bBackendAfter.Get(root, ctx.Config.KeySource); !errors.Is(err, keybackend.ErrKeyNotFound) {
		t.Fatalf("B should no longer be able to decrypt after removal, got: %v", err)
	}

	// A must still be able to decrypt.
	withGNUPGHome(t, a.home)
	aBackend, err := resolveBackend(ctx.Config)
	if err != nil {
		t.Fatalf("resolveBackend: %v", err)
	}
	if _, err := aBackend.Get(root, ctx.Config.KeySource); err != nil {
		t.Fatalf("A should still be able to decrypt after removing B: %v", err)
	}
}

func TestAddUserRequiresGPGBackend(t *testing.T) {
	root := newTestRepo(t)
	_ = root
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.AddUser("whatever"); err == nil {
		t.Fatalf("expected error calling AddUser on a non-gpg-backed repo")
	}
	if _, err := ctx.RemoveUser("whatever"); err == nil {
		t.Fatalf("expected error calling RemoveUser on a non-gpg-backed repo")
	}
}
