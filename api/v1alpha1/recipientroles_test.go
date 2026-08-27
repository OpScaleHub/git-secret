package v1alpha1

import "testing"

func TestParseAndFormatRecipientRoles(t *testing.T) {
	const fpA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const fpB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	const fpC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"

	ann := map[string]string{
		RecipientRolesAnnotation: fpA + ":controller, " + fpB + ":recovery," + fpC + ":bogus",
	}
	roles := ParseRecipientRoles(ann)
	if roles[fpA] != RoleController {
		t.Errorf("fpA role = %q, want controller", roles[fpA])
	}
	if roles[fpB] != RoleRecovery {
		t.Errorf("fpB role = %q, want recovery", roles[fpB])
	}
	if _, ok := roles[fpC]; ok {
		t.Errorf("bogus role should have been dropped, got %q", roles[fpC])
	}

	// Round-trips, sorted, human/default omitted.
	roles["dddd"] = RoleHuman
	got := FormatRecipientRoles(roles)
	want := fpA + ":controller," + fpB + ":recovery"
	if got != want {
		t.Errorf("FormatRecipientRoles = %q, want %q", got, want)
	}

	if FormatRecipientRoles(map[string]RecipientRole{"x": RoleHuman}) != "" {
		t.Error("all-human map should format to empty (annotation should be deleted)")
	}
	if ParseRecipientRoles(nil) == nil {
		t.Error("ParseRecipientRoles(nil) should return a non-nil empty map")
	}
}
