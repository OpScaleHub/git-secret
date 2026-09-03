package webhook

import (
	"context"
	"fmt"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// caBundleInjector patches webhookConfigName's clientConfig.caBundle with
// caPEM once the manager's client is ready. The self-signed CA changes on
// every controller restart, so this keeps the ValidatingWebhookConfiguration
// in sync without cert-manager.
//
// It is a LeaderElectionRunnable that requires leadership: the CA it would
// publish is this pod's own self-signed CA, and the ValidatingWebhook-
// Configuration.caBundle holds exactly one. With more than one replica the
// non-elected pods still serve the webhook with their own different certs,
// so a shared cert (cert-manager, or a shared Secret) is the only way to run
// the webhook HA -- until then the chart pins replicaCount: 1 whenever the
// webhook is enabled. Gating on leadership at least keeps a mis-scaled
// deployment from turning into a write-storm on the cluster-scoped config.
type caBundleInjector struct {
	mgr               ctrl.Manager
	webhookConfigName string
	caPEM             []byte
}

// NeedLeaderElection makes this run only on the elected leader.
func (c *caBundleInjector) NeedLeaderElection() bool { return true }

func (c *caBundleInjector) Start(ctx context.Context) error {
	client := c.mgr.GetClient()
	var cfg admissionregv1.ValidatingWebhookConfiguration
	if err := client.Get(ctx, types.NamespacedName{Name: c.webhookConfigName}, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			// The chart may not have installed it (webhook disabled).
			// Not fatal -- the handler simply never gets called.
			ctrl.Log.WithName("webhook").Info("ValidatingWebhookConfiguration not found; skipping caBundle injection", "name", c.webhookConfigName)
			return nil
		}
		return fmt.Errorf("webhook: get %s: %w", c.webhookConfigName, err)
	}
	changed := false
	for i := range cfg.Webhooks {
		if string(cfg.Webhooks[i].ClientConfig.CABundle) != string(c.caPEM) {
			cfg.Webhooks[i].ClientConfig.CABundle = c.caPEM
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := client.Update(ctx, &cfg); err != nil {
		return fmt.Errorf("webhook: patch caBundle on %s: %w", c.webhookConfigName, err)
	}
	ctrl.Log.WithName("webhook").Info("injected caBundle", "name", c.webhookConfigName)
	return nil
}

// InjectCABundle returns a leader-gated manager.Runnable that keeps
// webhookConfigName's caBundle equal to caPEM. Requires get/update on
// validatingwebhookconfigurations (the chart scopes update/patch to this
// one config by name).
func InjectCABundle(mgr ctrl.Manager, webhookConfigName string, caPEM []byte) manager.Runnable {
	return &caBundleInjector{mgr: mgr, webhookConfigName: webhookConfigName, caPEM: caPEM}
}
