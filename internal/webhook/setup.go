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

// InjectCABundle returns a manager.Runnable that patches
// webhookConfigName's every webhook clientConfig.caBundle with caPEM, once
// the manager's client is ready. The self-signed CA changes on every
// controller restart, so this keeps the ValidatingWebhookConfiguration in
// sync without cert-manager. Requires get/update on
// validatingwebhookconfigurations.
func InjectCABundle(mgr ctrl.Manager, webhookConfigName string, caPEM []byte) manager.Runnable {
	return manager.RunnableFunc(func(ctx context.Context) error {
		c := mgr.GetClient()
		var cfg admissionregv1.ValidatingWebhookConfiguration
		if err := c.Get(ctx, types.NamespacedName{Name: webhookConfigName}, &cfg); err != nil {
			if apierrors.IsNotFound(err) {
				// The chart may not have installed it (webhook disabled).
				// Not fatal -- the handler simply never gets called.
				ctrl.Log.WithName("webhook").Info("ValidatingWebhookConfiguration not found; skipping caBundle injection", "name", webhookConfigName)
				return nil
			}
			return fmt.Errorf("webhook: get %s: %w", webhookConfigName, err)
		}
		changed := false
		for i := range cfg.Webhooks {
			if string(cfg.Webhooks[i].ClientConfig.CABundle) != string(caPEM) {
				cfg.Webhooks[i].ClientConfig.CABundle = caPEM
				changed = true
			}
		}
		if !changed {
			return nil
		}
		if err := c.Update(ctx, &cfg); err != nil {
			return fmt.Errorf("webhook: patch caBundle on %s: %w", webhookConfigName, err)
		}
		ctrl.Log.WithName("webhook").Info("injected caBundle", "name", webhookConfigName)
		return nil
	})
}
