package v1alpha1

import (
	"sort"
	"strings"
)

// RecipientRolesAnnotation carries the role of each recipient fingerprint
// on a GitSecret, as a comma-separated "<fingerprint>:<role>" list, e.g.
//
//	keyfold.opscalehub.io/recipient-roles: "ABC...123:controller,DEF...456:recovery"
//
// It is a convention, not part of the decrypt path -- the controller never
// consults it. Its purpose is operational: making it obvious which
// recipients are the always-on controller identity, which are humans, and
// which are the offline recovery keys that must never be removed.
// keyfold reads and writes it; a fingerprint with no entry is a
// plain "human" recipient.
const RecipientRolesAnnotation = "keyfold.opscalehub.io/recipient-roles"

// Provenance annotations, stamped by keyfold when it runs inside a
// Git working tree: the commit the plaintext was sealed from, and the
// repository's origin URL. Informational -- the controller mirrors
// SourceRevisionAnnotation into status.sourceRevision so an operator can
// answer "which commit produced this Secret?" without leaving the cluster.
const (
	SourceRevisionAnnotation = "keyfold.opscalehub.io/source-revision"
	SourceRepoAnnotation     = "keyfold.opscalehub.io/source-repo"
)

// LegacyGroup is the API group (and annotation prefix) GitSecrets used
// before the project was renamed to Keyfold. Objects and annotations under
// it are still *read* -- never written -- so an existing install migrates
// without re-sealing anything; see UPGRADING.md.
const LegacyGroup = "git-secret.opscalehub.io"

// LegacyAnnotationKey maps a current annotation key to its pre-rename
// equivalent ("keyfold.opscalehub.io/x" -> "git-secret.opscalehub.io/x").
func LegacyAnnotationKey(key string) string {
	if rest, ok := strings.CutPrefix(key, GroupVersion.Group+"/"); ok {
		return LegacyGroup + "/" + rest
	}
	return key
}

// Annotation returns annotations[key], falling back to the pre-rename key
// for objects sealed (or Namespaces annotated) before the rename.
func Annotation(annotations map[string]string, key string) string {
	if v, ok := annotations[key]; ok {
		return v
	}
	return annotations[LegacyAnnotationKey(key)]
}

// RecipientRole classifies a recipient. See RecipientRolesAnnotation.
type RecipientRole string

const (
	// RoleHuman is an operator who seals/reviews locally. The default when
	// a fingerprint has no explicit role.
	RoleHuman RecipientRole = "human"
	// RoleController is a keyfold-controller identity (one per cluster).
	RoleController RecipientRole = "controller"
	// RoleRecovery is an offline key held outside any cluster and outside
	// any operator's daily keyring -- the disaster-recovery backstop. Every
	// production GitSecret should have at least one (threat-model
	// invariant #1); keyfold refuses to remove the last one
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
	raw := Annotation(annotations, RecipientRolesAnnotation)
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
