package v1alpha1

import "testing"

func TestAnnotation_FallsBackToPreRenameKey(t *testing.T) {
	if got := LegacyAnnotationKey(SourceRevisionAnnotation); got != "git-secret.opscalehub.io/source-revision" {
		t.Fatalf("LegacyAnnotationKey = %q", got)
	}
	legacyOnly := map[string]string{"git-secret.opscalehub.io/source-revision": "old"}
	if got := Annotation(legacyOnly, SourceRevisionAnnotation); got != "old" {
		t.Errorf("legacy-only: got %q, want old", got)
	}
	both := map[string]string{"git-secret.opscalehub.io/source-revision": "old", SourceRevisionAnnotation: "new"}
	if got := Annotation(both, SourceRevisionAnnotation); got != "new" {
		t.Errorf("both set: got %q, want the current key's value", got)
	}
	roles := ParseRecipientRoles(map[string]string{"git-secret.opscalehub.io/recipient-roles": "ABCD:recovery"})
	if roles["ABCD"] != RoleRecovery {
		t.Errorf("ParseRecipientRoles ignored the pre-rename key: %v", roles)
	}
}
