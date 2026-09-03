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
		ObjectMeta: metav1.ObjectMeta{
			Name:        "downtime-secrets",
			Namespace:   "downtime",
			Annotations: map[string]string{gitsecretv1alpha1.SourceRevisionAnnotation: "deadbeefcafe"},
		},
		Spec: spec,
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
	if updated.Status.RecipientCount != 1 || len(updated.Status.Recipients) != 1 || updated.Status.Recipients[0] != fpr {
		t.Errorf("status recipients = %v (count %d), want [%s] (1)", updated.Status.Recipients, updated.Status.RecipientCount, fpr)
	}
	if updated.Status.SourceRevision != "deadbeefcafe" {
		t.Errorf("status.sourceRevision = %q, want deadbeefcafe", updated.Status.SourceRevision)
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

// TestReconcile_RevertsDriftOnOwnedSecret is the reconciliation/drift-
// correction property asked about directly: if the target Secret is
// edited out-of-band (kubectl patch/edit, or anything else), the next
// reconcile must revert it back to match the GitSecret's decrypted
// content -- self-healing equivalent to what ArgoCD's own automated
// sync already provides elsewhere in this stack, but driven by this
// controller's own Owns(&corev1.Secret{}) watch (see SetupWithManager),
// not a poll interval.
//
// This test alone would NOT have caught the real bug this exact
// scenario surfaced: a real apiserver merges StringData into the
// existing Data map rather than replacing it, so an out-of-band key
// added directly to .data survived every reconcile indefinitely until
// Reconcile started clearing secret.Data before setting StringData.
// The fake client used here doesn't reproduce that merge semantics at
// all (Data comes back nil, StringData round-trips as given), so this
// test's EXTRA_KEY_NOT_IN_GITSECRET assertion passes regardless of
// whether that fix is present. Caught instead by testing the real
// controller against a real cluster with a real out-of-band `kubectl
// patch` -- kept here as a regression test for the reconcile logic
// itself, not as proof of the apiserver-merge behavior.
func TestReconcile_RevertsDriftOnOwnedSecret(t *testing.T) {
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

	// First reconcile: establishes the correct baseline.
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("initial Reconcile: %v", err)
	}

	// Simulate exactly what the question asked: something changes an
	// arbitrary value directly on the live target Secret, bypassing the
	// GitSecret entirely -- e.g. a `kubectl patch`/`kubectl edit`, or a
	// bug in some other controller that also happens to touch it.
	var drifted corev1.Secret
	if err := fakeClient.Get(context.Background(), namespacedName("downtime", "downtime-secrets"), &drifted); err != nil {
		t.Fatal(err)
	}
	// The fake client (unlike a real apiserver's admission) doesn't
	// merge StringData into Data on read-back, so Data may come back
	// nil here even though a real cluster would have it populated --
	// write via StringData to match how CreateOrUpdate itself sets
	// values, keeping this test meaningful against both.
	if drifted.StringData == nil {
		drifted.StringData = map[string]string{}
	}
	drifted.StringData["USERNAME"] = "attacker-controlled-or-just-wrong"
	drifted.StringData["EXTRA_KEY_NOT_IN_GITSECRET"] = "should not survive either"
	if err := fakeClient.Update(context.Background(), &drifted); err != nil {
		t.Fatalf("simulate drift: %v", err)
	}

	// In a real cluster this second reconcile is triggered automatically
	// by the Owns(&corev1.Secret{}) watch firing on the Update above --
	// the fake client here doesn't run that watch loop, so the test
	// calls Reconcile directly to exercise the same code path a real
	// watch-triggered reconcile would run.
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("drift-correcting Reconcile: %v", err)
	}

	var corrected corev1.Secret
	if err := fakeClient.Get(context.Background(), namespacedName("downtime", "downtime-secrets"), &corrected); err != nil {
		t.Fatal(err)
	}
	if corrected.StringData["USERNAME"] != "admin" {
		t.Errorf("USERNAME not reverted: got %q, want %q", corrected.StringData["USERNAME"], "admin")
	}
	if corrected.StringData["PASSWORD"] != "hunter2" {
		t.Errorf("PASSWORD not reverted: got %q, want %q", corrected.StringData["PASSWORD"], "hunter2")
	}
	if _, stillPresent := corrected.StringData["EXTRA_KEY_NOT_IN_GITSECRET"]; stillPresent {
		t.Error("out-of-band key survived reconcile -- CreateOrUpdate's mutate function must fully replace StringData, not merge into existing data")
	}
}

// TestReconcile_SteadyStateStopsWritingStatus pins #77 item 1: once a
// GitSecret is synced, reconciling it again with nothing changed must not
// write status. An unconditional Status().Update returns through the
// controller's own GitSecret watch and re-enqueues the object, so a
// per-reconcile timestamp bump reconciles forever. The proxy for "did it
// write" is the object's resourceVersion.
func TestReconcile_SteadyStateStopsWritingStatus(t *testing.T) {
	gnupgHome := shortTempDir(t)
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	spec, err := sealer.Seal("downtime", "downtime-secrets", map[string]string{"K": "v"}, []string{fpr})
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

	// First reconcile: establishes the target Secret + status.
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("initial Reconcile: %v", err)
	}
	var afterFirst gitsecretv1alpha1.GitSecret
	if err := fakeClient.Get(context.Background(), req.NamespacedName, &afterFirst); err != nil {
		t.Fatal(err)
	}
	rvAfterFirst := afterFirst.ResourceVersion
	if afterFirst.Status.SyncedKeys != 1 {
		t.Fatalf("first reconcile did not sync: status = %+v", afterFirst.Status)
	}

	// Several more reconciles with nothing changed -- the situation a
	// self-triggered re-enqueue would create.
	for i := 0; i < 5; i++ {
		if _, err := r.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("steady-state Reconcile %d: %v", i, err)
		}
	}

	var afterSteady gitsecretv1alpha1.GitSecret
	if err := fakeClient.Get(context.Background(), req.NamespacedName, &afterSteady); err != nil {
		t.Fatal(err)
	}
	if afterSteady.ResourceVersion != rvAfterFirst {
		t.Errorf("steady-state reconcile wrote the object (resourceVersion %s -> %s); the status write re-triggers the reconcile loop",
			rvAfterFirst, afterSteady.ResourceVersion)
	}
	// It must still report Ready -- quiet, not broken.
	ready := false
	for _, c := range afterSteady.Status.Conditions {
		if c.Type == conditionReady && c.Status == metav1.ConditionTrue {
			ready = true
		}
	}
	if !ready {
		t.Errorf("object lost its Ready condition after steady-state reconciles: %+v", afterSteady.Status.Conditions)
	}
}

// TestReconcile_DoesNotClobberUnownedSecret: a Secret with the target name
// already exists and is managed by something else (no owner reference back
// to this GitSecret). Reconcile must leave it completely untouched and
// report a TargetConflict condition, not silently clear its data and adopt
// it.
func TestReconcile_DoesNotClobberUnownedSecret(t *testing.T) {
	gnupgHome := shortTempDir(t)
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	spec, err := sealer.Seal("downtime", "downtime-secrets", map[string]string{"OURS": "from-gitsecret"}, []string{fpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	gs := &gitsecretv1alpha1.GitSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "downtime-secrets", Namespace: "downtime"},
		Spec:       spec,
	}
	preExisting := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "downtime-secrets", Namespace: "downtime"},
		Data:       map[string][]byte{"THEIRS": []byte("managed-elsewhere")},
	}

	scheme := newScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gs, preExisting).
		WithStatusSubresource(&gitsecretv1alpha1.GitSecret{}).
		Build()

	r := &GitSecretReconciler{Client: fakeClient}
	req := ctrl.Request{NamespacedName: namespacedName("downtime", "downtime-secrets")}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var after corev1.Secret
	if err := fakeClient.Get(context.Background(), namespacedName("downtime", "downtime-secrets"), &after); err != nil {
		t.Fatal(err)
	}
	if string(after.Data["THEIRS"]) != "managed-elsewhere" {
		t.Errorf("pre-existing Secret data was modified: %#v", after.Data)
	}
	if _, ours := after.Data["OURS"]; ours {
		t.Error("controller wrote its own key into a Secret it does not own")
	}
	if _, ours := after.StringData["OURS"]; ours {
		t.Error("controller wrote its own key (StringData) into a Secret it does not own")
	}
	if len(after.OwnerReferences) != 0 {
		t.Errorf("controller adopted an unowned Secret: %#v", after.OwnerReferences)
	}

	var updated gitsecretv1alpha1.GitSecret
	if err := fakeClient.Get(context.Background(), namespacedName("downtime", "downtime-secrets"), &updated); err != nil {
		t.Fatal(err)
	}
	var ready *metav1.Condition
	for i := range updated.Status.Conditions {
		if updated.Status.Conditions[i].Type == conditionReady {
			ready = &updated.Status.Conditions[i]
		}
	}
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "TargetConflict" {
		t.Errorf("Ready condition = %+v, want False/TargetConflict", ready)
	}
}

// TestReconcile_AdoptsUnownedSecretWhenOptedIn: same collision, but
// spec.target.adopt is set, so the controller is expected to take the
// Secret over.
func TestReconcile_AdoptsUnownedSecretWhenOptedIn(t *testing.T) {
	gnupgHome := shortTempDir(t)
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	spec, err := sealer.Seal("downtime", "downtime-secrets", map[string]string{"OURS": "from-gitsecret"}, []string{fpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	spec.Target.Adopt = true
	gs := &gitsecretv1alpha1.GitSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "downtime-secrets", Namespace: "downtime"},
		Spec:       spec,
	}
	preExisting := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "downtime-secrets", Namespace: "downtime"},
		Data:       map[string][]byte{"THEIRS": []byte("managed-elsewhere")},
	}

	scheme := newScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gs, preExisting).
		WithStatusSubresource(&gitsecretv1alpha1.GitSecret{}).
		Build()

	r := &GitSecretReconciler{Client: fakeClient}
	req := ctrl.Request{NamespacedName: namespacedName("downtime", "downtime-secrets")}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var after corev1.Secret
	if err := fakeClient.Get(context.Background(), namespacedName("downtime", "downtime-secrets"), &after); err != nil {
		t.Fatal(err)
	}
	if after.StringData["OURS"] != "from-gitsecret" {
		t.Errorf("adopted Secret missing our data: %#v", after.StringData)
	}
	if len(after.OwnerReferences) != 1 || after.OwnerReferences[0].Kind != "GitSecret" {
		t.Errorf("adopted Secret not owned by the GitSecret: %#v", after.OwnerReferences)
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
