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

// writeK8sSkeleton writes a minimal manifest with just the object
// identity fields (apiVersion/kind/metadata.name) EncryptK8sValue needs
// to bind a value to before any stringData entry exists yet -- the
// normal encrypt-value workflow (start from a manifest skeleton, encrypt
// each secret value one at a time, paste the blobs in by hand).
func writeK8sSkeleton(t *testing.T, root, path, name string) {
	t.Helper()
	writeRepoFile(t, root, path, fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
stringData: {}
`, name))
}

func TestEncryptDecryptK8sValueRoundTrip(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")
	writeK8sSkeleton(t, root, "deploy/app-secret.yaml", "app")

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

	out, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml", "")
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

// TestDecryptK8sManifestRejectsRetargetedIdentity pins the fix for
// issue #23: per-value ciphertext used to authenticate against nothing
// but the file path and stringData key, so moving already-valid
// ciphertext into a manifest with a different metadata.name (or
// namespace) decrypted successfully anyway. AAD now includes
// apiVersion/kind/metadata.name/namespace, so a retargeted object fails
// to decrypt instead of silently authenticating.
func TestDecryptK8sManifestRejectsRetargetedIdentity(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")
	writeK8sSkeleton(t, root, "deploy/app-secret.yaml", "app")

	blob, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "DB_PASSWORD", "hunter2")
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
	}

	// Same file, same key, but a different object name -- the ciphertext
	// is now attached to a different Secret than it was sealed for.
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: attacker-copy
stringData:
  DB_PASSWORD: %q
`, blob)
	writeRepoFile(t, root, "deploy/app-secret.yaml", manifest)

	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml", ""); err == nil {
		t.Fatalf("expected DecryptK8sManifest to reject ciphertext retargeted to a different metadata.name")
	}
}

// TestDecryptK8sManifestRejectsNamespaceOverrideMismatch pins the other
// half of issue #23: `apply -n NAMESPACE` must not be able to silently
// retarget an already-encrypted value to a namespace it wasn't sealed
// for -- decryption must fail closed instead.
func TestDecryptK8sManifestRejectsNamespaceOverrideMismatch(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")
	writeRepoFile(t, root, "deploy/app-secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: app
  namespace: prod
stringData: {}
`)

	blob, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "DB_PASSWORD", "hunter2")
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
	}
	writeRepoFile(t, root, "deploy/app-secret.yaml", fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: app
  namespace: prod
stringData:
  DB_PASSWORD: %q
`, blob))

	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml", "prod"); err != nil {
		t.Fatalf("DecryptK8sManifest with matching -n override: %v", err)
	}
	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml", "staging"); err == nil {
		t.Fatalf("expected DecryptK8sManifest to reject a -n override that doesn't match the sealed namespace")
	}
}

// TestDecryptK8sManifestRejectsAnchoredValue pins the fix for issue #24:
// a YAML anchor on an encrypted stringData value would let decryption
// copy the plaintext into every place in the document that aliases it
// (e.g. metadata.annotations), since stringData's write-only guarantee
// doesn't extend to the rest of the manifest.
func TestDecryptK8sManifestRejectsAnchoredValue(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")
	writeK8sSkeleton(t, root, "deploy/app-secret.yaml", "app")

	blob, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "DB_PASSWORD", "hunter2")
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
	}
	// The anchor (&pw) must appear before its alias (*pw) in document
	// order -- YAML doesn't allow forward references -- so stringData
	// comes first here even though a real manifest would put metadata
	// first; field order doesn't matter to the parsing/binding logic
	// under test.
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
stringData:
  DB_PASSWORD: &pw %q
metadata:
  name: app
  annotations:
    leaked: *pw
`, blob)
	writeRepoFile(t, root, "deploy/app-secret.yaml", manifest)

	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml", ""); err == nil {
		t.Fatalf("expected DecryptK8sManifest to reject an anchored stringData value")
	}
}

// TestPreCommitAndVerifyCatchUnencryptedK8sSecretValue pins the fix for
// issue #15/#25: k8s_secret_paths manifests were previously invisible to
// both pre-commit and verify, so a plaintext stringData value sitting
// next to real ciphertext (the "19 of 20 keys encrypted, one was never
// encrypted" shape) passed both checks silently.
func TestPreCommitAndVerifyCatchUnencryptedK8sSecretValue(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")
	commitInitConfig(t, root)
	writeK8sSkeleton(t, root, "deploy/app-secret.yaml", "app")

	blob, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "OIDC_CLIENT_SECRET", "s3cr3t-value")
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
	}
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: app
stringData:
  OIDC_CLIENT_SECRET: %q
  ZARRINPAL_MERCHANT_ID: CHANGE_ME
`, blob)
	writeRepoFile(t, root, "deploy/app-secret.yaml", manifest)
	runGit(t, root, "add", "deploy/app-secret.yaml")

	if err := ctx.HookPreCommit(); err == nil {
		t.Fatalf("expected HookPreCommit to refuse an unencrypted k8s_secret_paths value")
	} else if !strings.Contains(err.Error(), "ZARRINPAL_MERCHANT_ID") {
		t.Fatalf("HookPreCommit error missing offending key: %v", err)
	}

	// Simulate a bypassed hook so verify has something to catch at HEAD.
	runGit(t, root, "commit", "-q", "--no-verify", "-m", "leak plaintext k8s value")
	problems, err := ctx.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	found := false
	for _, p := range problems {
		if strings.Contains(p, "ZARRINPAL_MERCHANT_ID") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Verify problems = %v, want one mentioning ZARRINPAL_MERCHANT_ID", problems)
	}
}

// TestPreCommitAndVerifyAllowAllowlistedK8sPlaintextKey checks the other
// side of the same fix: a plaintext value explicitly allowlisted via
// k8s_plaintext_keys must not be flagged.
func TestPreCommitAndVerifyAllowAllowlistedK8sPlaintextKey(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg, err := config.Load(root)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.K8sSecretPaths = append(cfg.K8sSecretPaths, "deploy/app-secret.yaml")
	cfg.K8sPlaintextKeys = map[string][]string{"deploy/app-secret.yaml": {"PLAIN_NOTE"}}
	if err := config.Save(root, cfg); err != nil {
		t.Fatalf("config.Save: %v", err)
	}
	ctx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	commitInitConfig(t, root)
	writeK8sSkeleton(t, root, "deploy/app-secret.yaml", "app")

	blob, err := ctx.EncryptK8sValue("deploy/app-secret.yaml", "OIDC_CLIENT_SECRET", "s3cr3t-value")
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
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
	runGit(t, root, "add", "deploy/app-secret.yaml")

	if err := ctx.HookPreCommit(); err != nil {
		t.Fatalf("HookPreCommit: unexpected error for allowlisted plaintext key: %v", err)
	}
	runGit(t, root, "commit", "-q", "--no-verify", "-m", "add k8s secret")

	problems, err := ctx.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("Verify problems = %v, want none", problems)
	}
}

func TestDecryptK8sManifestRejectsSwappedCiphertext(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")
	writeK8sSkeleton(t, root, "deploy/app-secret.yaml", "app")

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

	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml", ""); err == nil {
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

	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml", ""); err == nil {
		t.Fatalf("expected DecryptK8sManifest to error on zero matched ciphertext values")
	}
}

func TestRotateKeysReencryptsK8sManifestValues(t *testing.T) {
	root := newTestRepo(t)
	if _, err := Init(InitOptions{Patterns: []string{"secrets/**"}}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := withK8sSecretPath(t, root, "deploy/app-secret.yaml")
	writeK8sSkeleton(t, root, "deploy/app-secret.yaml", "app")

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
	out, err := newCtx.DecryptK8sManifest("deploy/app-secret.yaml", "")
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
	if _, err := ctx.DecryptK8sManifest("deploy/app-secret.yaml", ""); err == nil {
		t.Fatalf("expected DecryptK8sManifest to reject a path absent from k8s_secret_paths")
	}
}
