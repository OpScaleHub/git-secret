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

	// LastSyncTime is when the target Secret was last successfully
	// written to match this object.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gsec
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.target.name`,priority=0
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Keys",type=integer,JSONPath=`.status.syncedKeys`
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
