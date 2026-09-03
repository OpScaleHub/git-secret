package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretTarget describes the plain Kubernetes Secret a GitSecret decrypts
// into.
type SecretTarget struct {
	// Name of the Secret to create/update. Defaults to the GitSecret's own
	// name when empty.
	// +optional
	Name string `json:"name,omitempty"`

	// Type is the Kubernetes Secret type applied to the target Secret.
	// Defaults to Opaque.
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`

	// Adopt lets the controller take over a Secret that already exists and
	// is not owned by this GitSecret, replacing its contents and attaching
	// an owner reference (so it is deleted with the GitSecret). Off by
	// default: a name collision with an independently-managed Secret is
	// reported as a "TargetConflict" Ready=False condition and the existing
	// Secret is left untouched, rather than being silently clobbered.
	// +optional
	Adopt bool `json:"adopt,omitempty"`
}

// GitSecretSpec is the desired state of a GitSecret: everything needed to
// reproduce a plaintext Secret without ever leaving ciphertext-at-rest.
type GitSecretSpec struct {
	// Target describes the Secret this object decrypts into.
	// +optional
	Target SecretTarget `json:"target,omitempty"`

	// EncryptedKey is the object's content-encryption key, GPG-encrypted
	// (ASCII-armored) to every current recipient -- see
	// internal/gpgutil.Encrypt. Only a GNUPGHOME holding one of those
	// recipients' private keys can unwrap it. Rotating recipients (adding
	// or removing a person, or the controller's own key) only ever
	// replaces this one field: EncryptedData is never re-encrypted, the
	// same cheap-rewrap property keybackend.GPGBackend already relies on
	// for whole-repo files.
	EncryptedKey string `json:"encryptedKey"`

	// Recipients lists the full GPG fingerprints EncryptedKey is wrapped
	// to, sorted. Written by git-secret-seal. It is informational -- the
	// authoritative recipient set is whatever EncryptedKey actually
	// encrypts to -- but it makes "who can decrypt this object" reviewable
	// in a plain YAML diff (adding a recipient becomes a visible one-line
	// change) instead of requiring the armored blob to be inspected with
	// gpg. sealer.VerifyRecipients cross-checks the count against the blob.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	Recipients []string `json:"recipients,omitempty"`

	// EncryptedData holds one ciphertext per target Secret key. Each value
	// is a crypto.Seal envelope (see crypto/crypto.go), base64-std-encoded
	// so it survives as plain YAML/JSON text, sealed under the key
	// EncryptedKey wraps, with this GitSecret's "<namespace>/<name>/<key>"
	// as additional authenticated data -- binding each ciphertext to
	// exactly the object and field it was sealed for, so copying an entry
	// into a different GitSecret (or renaming/moving this one) fails to
	// decrypt rather than silently applying to the wrong place.
	//
	// Bounded to keep a malformed or hostile object from forcing the
	// controller to decrypt an unbounded amount of data per reconcile; the
	// resulting Secret is still subject to the apiserver's own ~1MiB cap.
	// +optional
	// +kubebuilder:validation:MaxProperties=1024
	EncryptedData map[string]string `json:"encryptedData,omitempty"`
}

// GitSecretStatus is the observed state of a GitSecret, reported by the
// controller after each reconcile.
type GitSecretStatus struct {
	// ObservedGeneration is the .metadata.generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions follows the standard Kubernetes condition convention.
	// The "Ready" type reflects whether the target Secret currently
	// matches this object's encrypted data.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SyncedKeys is the number of EncryptedData entries currently
	// decrypted into the target Secret.
	// +optional
	SyncedKeys int `json:"syncedKeys,omitempty"`

	// LastSyncTime is when the controller last wrote something for this
	// object -- created or corrected the target Secret, or moved a status
	// field. It is not refreshed on a steady-state reconcile where nothing
	// changed (the controller deliberately skips that write so it does not
	// re-trigger itself), so it marks the last actual change, not the last
	// time the object was looked at.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Recipients mirrors spec.recipients as observed at the last reconcile,
	// so `kubectl get gitsecret -o yaml` shows the current decrypt set
	// without reading the spec. Empty if the object predates the field or
	// was sealed by an older git-secret-seal.
	// +optional
	// +listType=set
	Recipients []string `json:"recipients,omitempty"`

	// RecipientCount is len(spec.recipients), surfaced as a printer column.
	// +optional
	RecipientCount int `json:"recipientCount,omitempty"`

	// SourceRevision echoes the git-secret.opscalehub.io/source-revision
	// annotation (the commit git-secret-seal sealed the plaintext from), so
	// `kubectl get gitsecret` answers "which commit produced this Secret?".
	// Empty if the object carries no provenance annotation.
	// +optional
	SourceRevision string `json:"sourceRevision,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gsec
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.target.name`,priority=0
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Keys",type=integer,JSONPath=`.status.syncedKeys`
// +kubebuilder:printcolumn:name="Recipients",type=integer,JSONPath=`.status.recipientCount`
// +kubebuilder:printcolumn:name="Revision",type=string,JSONPath=`.status.sourceRevision`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// GitSecret decrypts into a plain Kubernetes Secret via a controller that
// holds one of the GPG recipient keys EncryptedKey is wrapped to. Unlike
// the ESO webhook bridge (cmd/git-secret-server), ciphertext lives inline
// in the object -- delivered by whatever already applies manifests to the
// cluster (ArgoCD, kubectl, ...), with no repo clone, deploy key, or
// network hop involved in decryption.
type GitSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GitSecretSpec   `json:"spec,omitempty"`
	Status GitSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GitSecretList is a list of GitSecret.
type GitSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GitSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GitSecret{}, &GitSecretList{})
}
