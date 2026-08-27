package v1alpha1

import (
	"sort"
	"strings"
)

// RecipientRolesAnnotation carries the role of each recipient fingerprint
// on a GitSecret, as a comma-separated "<fingerprint>:<role>" list, e.g.
//
//	git-secret.opscalehub.io/recipient-roles: "ABC...123:controller,DEF...456:recovery"
//
// It is a convention, not part of the decrypt path -- the controller never
// consults it. Its purpose is operational: making it obvious which
// recipients are the always-on controller identity, which are humans, and
// which are the offline recovery keys that must never be removed.
// git-secret-seal reads and writes it; a fingerprint with no entry is a
// plain "human" recipient.
const RecipientRolesAnnotation = "git-secret.opscalehub.io/recipient-roles"

// RecipientRole classifies a recipient. See RecipientRolesAnnotation.
type RecipientRole string

const (
	// RoleHuman is an operator who seals/reviews locally. The default when
	// a fingerprint has no explicit role.
	RoleHuman RecipientRole = "human"
	// RoleController is a git-secret-controller identity (one per cluster).
	RoleController RecipientRole = "controller"
	// RoleRecovery is an offline key held outside any cluster and outside
	// any operator's daily keyring -- the disaster-recovery backstop. Every
	// production GitSecret should have at least one (threat-model
	// invariant #1); git-secret-seal refuses to remove the last one
	// without --force.
	RoleRecovery RecipientRole = "recovery"
	// RoleDeprecated is a recipient being phased out: still wrapped to, so
	// it can still decrypt, but flagged so a later rewrap drops it.
	RoleDeprecated RecipientRole = "deprecated"
)

// ValidRecipientRole reports whether r is one of the known roles.
func ValidRecipientRole(r RecipientRole) bool {
	switch r {
	case RoleHuman, RoleController, RoleRecovery, RoleDeprecated:
		return true
	}
	return false
}

// ParseRecipientRoles reads the RecipientRolesAnnotation value from
// annotations. Unknown or malformed entries are skipped. Fingerprints are
// upper-cased so lookups are case-insensitive.
func ParseRecipientRoles(annotations map[string]string) map[string]RecipientRole {
	out := map[string]RecipientRole{}
	raw := annotations[RecipientRolesAnnotation]
	if raw == "" {
		return out
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		fp, role, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		fp = strings.ToUpper(strings.TrimSpace(fp))
		rr := RecipientRole(strings.TrimSpace(role))
		if fp == "" || !ValidRecipientRole(rr) {
			continue
		}
		out[fp] = rr
	}
	return out
}

// FormatRecipientRoles renders roles back to an annotation value, sorted
// by fingerprint for a stable diff. Entries with the default "human" role
// are omitted to keep the annotation short; an empty result means the
// caller should delete the annotation entirely.
func FormatRecipientRoles(roles map[string]RecipientRole) string {
	parts := make([]string, 0, len(roles))
	for fp, role := range roles {
		if role == "" || role == RoleHuman || !ValidRecipientRole(role) {
			continue
		}
		parts = append(parts, strings.ToUpper(fp)+":"+string(role))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
