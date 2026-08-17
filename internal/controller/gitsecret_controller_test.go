package controller

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gitsecretv1alpha1 "github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

// genTestKey duplicates internal/sealer's test helper (unexported there,
// and this package shouldn't depend on _test.go files across packages).
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
Name-Real: controller test
Name-Email: controller-test@example.invalid
Expire-Date: 0
%no-protection
%commit
`
	cmd := exec.Command("gpg", "--batch", "--gen-key")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	cmd.Stdin = strings.NewReader(batch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gpg --gen-key: %v\n%s", err, out)
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

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gitsecretv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func TestReconcile_CreatesTargetSecret(t *testing.T) {
	gnupgHome := t.TempDir()
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		t.Fatal(err)
	}
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	spec, err := sealer.Seal("downtime", "downtime-secrets", map[string]string{
		"USERNAME": "admin",
		"PASSWORD": "hunter2",
	}, []string{fpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	gs := &gitsecretv1alpha1.GitSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "downtime-secrets", Namespace: "downtime"},
		Spec:       spec,
	}

	scheme := newScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gs).
		WithStatusSubresource(&gitsecretv1alpha1.GitSecret{}).
		Build()

	r := &GitSecretReconciler{Client: fakeClient}
	req := ctrl.Request{NamespacedName: namespacedName("downtime", "downtime-secrets")}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var secret corev1.Secret
	if err := fakeClient.Get(context.Background(), namespacedName("downtime", "downtime-secrets"), &secret); err != nil {
		t.Fatalf("target Secret was not created: %v", err)
	}
	if secret.Type != corev1.SecretTypeOpaque {
		t.Errorf("Secret type = %q, want Opaque", secret.Type)
	}
	if secret.StringData["USERNAME"] != "admin" || secret.StringData["PASSWORD"] != "hunter2" {
		t.Errorf("decrypted Secret data mismatch: %#v", secret.StringData)
	}
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].Kind != "GitSecret" {
		t.Errorf("expected target Secret to be owned by the GitSecret, got %#v", secret.OwnerReferences)
	}

	var updated gitsecretv1alpha1.GitSecret
	if err := fakeClient.Get(context.Background(), namespacedName("downtime", "downtime-secrets"), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.SyncedKeys != 2 {
		t.Errorf("status.syncedKeys = %d, want 2", updated.Status.SyncedKeys)
	}
	found := false
	for _, c := range updated.Status.Conditions {
		if c.Type == conditionReady {
			found = true
			if c.Status != metav1.ConditionTrue {
				t.Errorf("Ready condition status = %s, want True", c.Status)
			}
		}
	}
	if !found {
		t.Error("no Ready condition set on GitSecret status")
	}
}

func TestReconcile_WrongKeyReportsFailureWithoutCreatingSecret(t *testing.T) {
	sealingHome := t.TempDir()
	if err := os.Chmod(sealingHome, 0o700); err != nil {
		t.Fatal(err)
	}
	sealFpr := genTestKey(t, sealingHome)

	// Seal to a key the controller's GNUPGHOME (set below) will NOT hold --
	// simulating a GitSecret sealed for a recipient the controller was
	// never given.
	t.Setenv("GNUPGHOME", sealingHome)
	spec, err := sealer.Seal("downtime", "downtime-secrets", map[string]string{"K": "v"}, []string{sealFpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	controllerHome := t.TempDir()
	if err := os.Chmod(controllerHome, 0o700); err != nil {
		t.Fatal(err)
	}
	genTestKey(t, controllerHome) // an unrelated key, so gpg is "available" but can't open spec.EncryptedKey
	t.Setenv("GNUPGHOME", controllerHome)

	gs := &gitsecretv1alpha1.GitSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "downtime-secrets", Namespace: "downtime"},
		Spec:       spec,
	}
	scheme := newScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gs).
		WithStatusSubresource(&gitsecretv1alpha1.GitSecret{}).
		Build()

	r := &GitSecretReconciler{Client: fakeClient}
	req := ctrl.Request{NamespacedName: namespacedName("downtime", "downtime-secrets")}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile returned an error (should report via status, not error out): %v", err)
	}

	var secret corev1.Secret
	err = fakeClient.Get(context.Background(), namespacedName("downtime", "downtime-secrets"), &secret)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected no target Secret to be created when unseal fails, got err=%v", err)
	}

	var updated gitsecretv1alpha1.GitSecret
	if err := fakeClient.Get(context.Background(), namespacedName("downtime", "downtime-secrets"), &updated); err != nil {
		t.Fatal(err)
	}
	var readyCond *metav1.Condition
	for i := range updated.Status.Conditions {
		if updated.Status.Conditions[i].Type == conditionReady {
			readyCond = &updated.Status.Conditions[i]
		}
	}
	if readyCond == nil {
		t.Fatal("no Ready condition set")
	}
	if readyCond.Status != metav1.ConditionFalse || readyCond.Reason != "UnsealFailed" {
		t.Errorf("Ready condition = %+v, want False/UnsealFailed", readyCond)
	}
}
