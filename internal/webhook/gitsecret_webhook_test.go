package webhook

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gitsecretv1alpha1 "github.com/OpScaleHub/git-secret/api/v1alpha1"
)

const (
	fpRecovery = "1111111111111111111111111111111111111111"
	fpHuman    = "2222222222222222222222222222222222222222"
)

func withStubbedVerify(t *testing.T, err error) {
	t.Helper()
	orig := verifyRecipients
	verifyRecipients = func(gitsecretv1alpha1.GitSecretSpec) error { return err }
	t.Cleanup(func() { verifyRecipients = orig })
}

func fakeClientWithNamespace(t *testing.T, name string, annotations map[string]string) *fake.ClientBuilder {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annotations}}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns)
}

func gitSecret(ns string, recipients ...string) *gitsecretv1alpha1.GitSecret {
	return &gitsecretv1alpha1.GitSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: ns},
		Spec:       gitsecretv1alpha1.GitSecretSpec{EncryptedKey: "x", Recipients: recipients},
	}
}

func TestValidate_RejectsRecipientMismatch(t *testing.T) {
	withStubbedVerify(t, errors.New("lists 2 fingerprint(s) but encryptedKey is wrapped to 1"))
	c := fakeClientWithNamespace(t, "prod", nil).Build()

	err := validate(context.Background(), c, gitSecret("prod", fpHuman))
	if err == nil || !strings.Contains(err.Error(), "does not match encryptedKey") {
		t.Fatalf("want recipient-mismatch rejection, got %v", err)
	}
}

func TestValidate_AllowsWhenConsistentAndNoNamespacePolicy(t *testing.T) {
	withStubbedVerify(t, nil)
	c := fakeClientWithNamespace(t, "prod", nil).Build()

	if err := validate(context.Background(), c, gitSecret("prod", fpHuman)); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

func TestValidate_EnforcesNamespaceRequiredRecipients(t *testing.T) {
	withStubbedVerify(t, nil)
	c := fakeClientWithNamespace(t, "prod", map[string]string{
		RequiredRecipientsAnnotation: fpRecovery + " , " + fpHuman,
	}).Build()

	// Missing the recovery fingerprint -> rejected.
	err := validate(context.Background(), c, gitSecret("prod", fpHuman))
	if err == nil || !strings.Contains(err.Error(), fpRecovery) {
		t.Fatalf("want rejection naming the missing recovery fpr, got %v", err)
	}

	// Both present (case-insensitive) -> allowed.
	if err := validate(context.Background(), c, gitSecret("prod", strings.ToLower(fpRecovery), fpHuman)); err != nil {
		t.Fatalf("expected allow when all required recipients present, got %v", err)
	}
}

func TestValidate_NoNamespaceObjectIsNotFatal(t *testing.T) {
	withStubbedVerify(t, nil)
	c := fakeClientWithNamespace(t, "other", nil).Build() // "prod" doesn't exist

	if err := validate(context.Background(), c, gitSecret("prod", fpHuman)); err != nil {
		t.Fatalf("a missing namespace object should not block admission, got %v", err)
	}
}
