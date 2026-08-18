// Package controller reconciles GitSecret objects (api/v1alpha1) into
// plain Kubernetes Secrets. All the actual cryptography lives in
// internal/sealer, kept deliberately free of any controller-runtime/client
// dependency so it stays unit-testable without a fake apiserver; this file
// is the thin Kubernetes-facing wrapper around it.
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gitsecretv1alpha1 "github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

// conditionReady is the standard "did the last reconcile succeed" status
// condition type, mirrored on every GitSecret this controller manages.
const conditionReady = "Ready"

// GitSecretReconciler decrypts GitSecret objects into Kubernetes Secrets.
// Unlike git-secret-server, it never clones a repo or makes an outbound
// network call: every input (ciphertext, recipients) already arrived as
// part of the GitSecret object itself via the normal apply path (ArgoCD,
// kubectl, ...), and the only secret this process itself needs is its own
// GPG private key, imported once at startup (see
// cmd/git-secret-controller).
type GitSecretReconciler struct {
	client.Client
}

// Reconcile implements the controller-runtime reconcile loop: fetch the
// GitSecret, unseal it, and create/update its target Secret to match.
func (r *GitSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var gs gitsecretv1alpha1.GitSecret
	if err := r.Get(ctx, req.NamespacedName, &gs); err != nil {
		if apierrors.IsNotFound(err) {
			// Deleted -- nothing to do. The target Secret is owned via
			// controller reference (see below), so garbage collection
			// already handles cleanup; we don't need to reconcile a
			// deletion path by hand.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get GitSecret: %w", err)
	}

	targetName := gs.Spec.Target.Name
	if targetName == "" {
		targetName = gs.Name
	}

	data, unsealErr := sealer.Unseal(gs.Namespace, gs.Name, gs.Spec)
	if unsealErr != nil {
		logger.Error(unsealErr, "unseal failed", "gitsecret", req.NamespacedName)
		r.setCondition(&gs, metav1.ConditionFalse, "UnsealFailed", unsealErr.Error())
		if statusErr := r.Status().Update(ctx, &gs); statusErr != nil {
			logger.Error(statusErr, "failed to record UnsealFailed status")
		}
		// Do not requeue tightly on a decrypt failure -- it will not
		// resolve itself without a spec or key-material change, both of
		// which already trigger a new reconcile via the watch. A wrong
		// recipient/expired key is an operator problem, not a transient
		// one; retrying every few seconds would just spam logs.
		return ctrl.Result{}, nil
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetName,
			Namespace: gs.Namespace,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Type = gs.Spec.Target.Type
		if secret.Type == "" {
			secret.Type = corev1.SecretTypeOpaque
		}
		// Kubernetes' apiserver *merges* StringData into the existing
		// Data map on write -- it does not clear keys already present
		// in Data that StringData doesn't mention. Left alone, that
		// means a key injected directly into .data out-of-band (a
		// `kubectl patch`, a bug in something else touching this
		// Secret) survives every reconcile forever, silently, since
		// CreateOrUpdate only ever adds/overwrites the keys this
		// GitSecret actually declares. Clearing Data first forces every
		// reconcile to produce a full mirror of gs.Spec.EncryptedData,
		// not a merge on top of whatever was already there -- confirmed
		// necessary by testing this drift-correction path against a
		// real cluster, not just the fake client (which doesn't
		// reproduce the apiserver's StringData-merge behavior at all).
		secret.Data = nil
		secret.StringData = data
		// Owning the target Secret (rather than ESO's adopt-in-place
		// Merge/Retain pattern) is deliberate here: a GitSecret created
		// fresh is the sole source of truth for its target, so deleting
		// it should delete the Secret too, same as sealed-secrets. This
		// is NOT used to adopt any already-existing, independently
		// managed Secret -- see docs/adr/0002 on why that's a separate,
		// explicitly-gated migration decision per target, not something
		// this controller does automatically.
		return controllerutil.SetControllerReference(&gs, secret, r.Client.Scheme())
	})
	if err != nil {
		logger.Error(err, "failed to create/update target Secret")
		r.setCondition(&gs, metav1.ConditionFalse, "ApplyFailed", err.Error())
		if statusErr := r.Status().Update(ctx, &gs); statusErr != nil {
			logger.Error(statusErr, "failed to record ApplyFailed status")
		}
		return ctrl.Result{}, err
	}
	if result != controllerutil.OperationResultNone {
		logger.Info("target Secret synced", "gitsecret", req.NamespacedName, "secret", targetName, "op", result)
	}

	gs.Status.ObservedGeneration = gs.Generation
	gs.Status.SyncedKeys = len(data)
	now := metav1.Now()
	gs.Status.LastSyncTime = &now
	r.setCondition(&gs, metav1.ConditionTrue, "Synced", fmt.Sprintf("decrypted %d key(s) into Secret/%s", len(data), targetName))
	if err := r.Status().Update(ctx, &gs); err != nil {
		return ctrl.Result{}, fmt.Errorf("update GitSecret status: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *GitSecretReconciler) setCondition(gs *gitsecretv1alpha1.GitSecret, status metav1.ConditionStatus, reason, message string) {
	meta := metav1.Condition{
		Type:               conditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: gs.Generation,
	}
	setStatusCondition(&gs.Status.Conditions, meta)
}

// setStatusCondition mirrors k8s.io/apimachinery/pkg/api/meta's
// SetStatusCondition (not imported directly to avoid pulling in the whole
// meta package for one helper): replaces an existing condition of the same
// Type in place, preserving LastTransitionTime unless Status actually
// changed, or appends a new one.
func setStatusCondition(conditions *[]metav1.Condition, newCond metav1.Condition) {
	if conditions == nil {
		return
	}
	for i, existing := range *conditions {
		if existing.Type != newCond.Type {
			continue
		}
		if existing.Status == newCond.Status {
			newCond.LastTransitionTime = existing.LastTransitionTime
		} else {
			newCond.LastTransitionTime = metav1.Now()
		}
		(*conditions)[i] = newCond
		return
	}
	newCond.LastTransitionTime = metav1.Now()
	*conditions = append(*conditions, newCond)
}

// SetupWithManager wires the reconciler into mgr, watching GitSecret
// objects and the Secrets they own (so an external edit/delete of the
// target Secret gets corrected on the next reconcile, same self-healing
// property ArgoCD's own automated sync already relies on elsewhere in this
// stack).
func (r *GitSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gitsecretv1alpha1.GitSecret{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

// namespacedName is a small convenience used by tests.
func namespacedName(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}
