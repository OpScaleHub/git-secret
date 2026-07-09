package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/config"
)

// withK8sSecretPath layers relPath onto the repo's k8s_secret_paths and
// returns a freshly-loaded Context reflecting that change (the Context
// returned by an earlier Load() call is a snapshot, not live).
func withK8sSecretPath(t *testing.T, root string, relPath string) *Context {
	t.Helper()
	cfg, err := config.Load(root)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.K8sSecretPaths = append(cfg.K8sSecretPaths, relPath)
	if err := config.Save(root, cfg); err != nil {
		t.Fatalf("config.Save: %v", err)
	}
	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return ctx
}

func TestEncryptDecryptK8sValueRoundTrip(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")

	blob, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "OIDC_CLIENT_SECRET", "s3cr3t-value")
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
	}
	if !strings.HasPrefix(blob, k8sValuePrefix) {
		t.Fatalf("EncryptK8sValue output = %q, want %s prefix", blob, k8sValuePrefix)
	}

	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: app
stringData:
  OIDC_CLIENT_SECRET: %q
  PLAIN_NOTE: not-a-secret
`, blob)
	writeRepoFile(t, root, "deploy/app-secret.yaml", manifest)

	out, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml")
	if err != nil {
		t.Fatalf("DecryptK8sManifest: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "s3cr3t-value") {
		t.Fatalf("decrypted manifest missing plaintext secret, got:\n%s", got)
	}
	if strings.Contains(got, k8sValuePrefix) {
		t.Fatalf("decrypted manifest still contains ciphertext marker, got:\n%s", got)
	}
	if !strings.Contains(got, "not-a-secret") {
		t.Fatalf("decrypted manifest lost the plaintext-already value, got:\n%s", got)
	}
}

func TestDecryptK8sManifestRejectsSwappedCiphertext(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")

	oidcBlob, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "OIDC_CLIENT_SECRET", "oidc-value")
	if err != nil {
		t.Fatalf("EncryptK8sValue(OIDC_CLIENT_SECRET): %v", err)
	}
	webhookBlob, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "WEBHOOK_SIGNING_KEY", "webhook-value")
	if err != nil {
		t.Fatalf("EncryptK8sValue(WEBHOOK_SIGNING_KEY): %v", err)
	}

	// Swap the two ciphertext blobs between keys — this is exactly the
	// attack the path+key AAD binding (k8sAAD) is meant to block.
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: app
stringData:
  OIDC_CLIENT_SECRET: %q
  WEBHOOK_SIGNING_KEY: %q
`, webhookBlob, oidcBlob)
	writeRepoFile(t, root, "deploy/app-secret.yaml", manifest)

	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml"); err == nil {
		t.Fatalf("expected DecryptK8sManifest to reject swapped ciphertext, got nil error")
	}
}

func TestDecryptK8sManifestErrorsWhenNoCiphertextMatched(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")

	writeRepoFile(t, root, "deploy/app-secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: app
stringData:
  PLAIN_NOTE: not-a-secret
`)

	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml"); err == nil {
		t.Fatalf("expected DecryptK8sManifest to error on zero matched ciphertext values")
	}
}

func TestRotateKeysReencryptsK8sManifestValues(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")

	blob, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "OIDC_CLIENT_SECRET", "oidc-value")
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
	}
	writeRepoFile(t, root, "deploy/app-secret.yaml", fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: app
stringData:
  OIDC_CLIENT_SECRET: %q
  PLAIN_NOTE: not-a-secret
`, blob))

	before, err := os.ReadFile(filepath.Join(root, "deploy/app-secret.yaml"))
	if err != nil {
		t.Fatalf("read manifest before rotate: %v", err)
	}

	result, err := ctx.RotateKeys()
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	found := false
	for _, p := range result.RotatedFiles {
		if p == "deploy/app-secret.yaml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RotatedFiles = %v, want to include deploy/app-secret.yaml", result.RotatedFiles)
	}

	after, err := os.ReadFile(filepath.Join(root, "deploy/app-secret.yaml"))
	if err != nil {
		t.Fatalf("read manifest after rotate: %v", err)
	}
	if string(after) == string(before) {
		t.Fatalf("manifest ciphertext unchanged after rotation")
	}
	if !strings.Contains(string(after), "not-a-secret") {
		t.Fatalf("rotation lost the plaintext-already value, got:\n%s", after)
	}

	newCtx, err := Load()
	if err != nil {
		t.Fatalf("Load after rotate: %v", err)
	}
	out, err := newCtx.DecryptK8sManifest("deploy/app-secret.yaml")
	if err != nil {
		t.Fatalf("DecryptK8sManifest after rotate (new key should work): %v", err)
	}
	if !strings.Contains(string(out), "oidc-value") {
		t.Fatalf("decrypted-after-rotate manifest missing original plaintext, got:\n%s", out)
	}
}

func TestK8sValueOpsRejectPathNotInK8sSecretPaths(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeRepoFile(t, root, "deploy/app-secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: app
stringData:
  PLAIN_NOTE: not-a-secret
`)

	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "KEY", "value"); err == nil {
		t.Fatalf("expected EncryptK8sValue to reject a path absent from k8s_secret_paths")
	}
	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml"); err == nil {
		t.Fatalf("expected DecryptK8sManifest to reject a path absent from k8s_secret_paths")
	}
}
