package controller

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gitsecretv1alpha1 "github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

// shortTempDir and genTestKey duplicate internal/sealer's test helpers
// (unexported there, and this package shouldn't depend on _test.go files
// across packages). See internal/sealer/sealer_test.go's shortTempDir doc
// comment for why gpg-agent specifically needs a short path, not
// t.TempDir() directly, to be reliable on macOS CI runners.
func shortTempDir(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "controller-test-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func genTestKey(t *testing.T, gnupgHome string) string {
	t.Helper()
	if !gpgutil.Available() {
		t.Skip("gpg not installed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("gpg-agent unreliable on windows CI runners")
	}

	cmd := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-generate-key", "controller test <controller-test@example.invalid>", "default", "default", "never")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	if out, err := cmd.CombinedOutput(); err != nil {
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

func newScheme(t *testing.T) *k8sruntime.Scheme {
	t.Helper()
	scheme := k8sruntime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gitsecretv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func TestReconcile_CreatesTargetSecret(t *testing.T) {
	gnupgHome := shortTempDir(t)
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
	sealingHome := shortTempDir(t)
	sealFpr := genTestKey(t, sealingHome)

	// Seal to a key the controller's GNUPGHOME (set below) will NOT hold --
	// simulating a GitSecret sealed for a recipient the controller was
	// never given.
	t.Setenv("GNUPGHOME", sealingHome)
	spec, err := sealer.Seal("downtime", "downtime-secrets", map[string]string{"K": "v"}, []string{sealFpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	controllerHome := shortTempDir(t)
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
