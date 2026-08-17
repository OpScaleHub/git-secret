// Package v1alpha1 contains the GitSecret API: a CRD-native alternative to
// the ESO webhook bridge (cmd/git-secret-server, docs/adr/0001) with
// ciphertext carried inline in the object instead of pulled from a cloned
// repo at request time. See docs/adr/0002-native-crd-controller.md for the
// full rationale.
//
// +kubebuilder:object:generate=true
// +groupName=git-secret.opscalehub.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "git-secret.opscalehub.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
