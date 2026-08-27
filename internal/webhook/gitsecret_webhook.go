package webhook

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	gitsecretv1alpha1 "github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

// WebhookPath is where the ValidatingWebhookConfiguration must point.
const WebhookPath = "/validate-git-secret-opscalehub-io-v1alpha1-gitsecret"

// RequiredRecipientsAnnotation, when set on a Namespace, lists GPG
// fingerprints (comma-separated) that every GitSecret in that namespace
// must include in spec.recipients -- e.g. to force an offline recovery key
// into every production object.
const RequiredRecipientsAnnotation = "git-secret.opscalehub.io/required-recipients"

// verifyRecipients is swappable in tests (the real one shells out to gpg).
var verifyRecipients = sealer.VerifyRecipients

// GitSecretValidator is the validating admission handler for GitSecret.
type GitSecretValidator struct {
	client  client.Client
	decoder admission.Decoder
}

// SetupWithManager registers the validator on mgr's webhook server.
func SetupWithManager(mgr ctrl.Manager) error {
	v := &GitSecretValidator{
		client:  mgr.GetClient(),
		decoder: admission.NewDecoder(mgr.GetScheme()),
	}
	mgr.GetWebhookServer().Register(WebhookPath, &admission.Webhook{Handler: v})
	return nil
}

// Handle implements admission.Handler.
func (v *GitSecretValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != "CREATE" && req.Operation != "UPDATE" {
		return admission.Allowed("")
	}
	var gs gitsecretv1alpha1.GitSecret
	if err := v.decoder.Decode(req, &gs); err != nil {
		return admission.Errored(400, fmt.Errorf("decode GitSecret: %w", err))
	}
	if err := validate(ctx, v.client, &gs); err != nil {
		return admission.Denied(err.Error())
	}
	return admission.Allowed("")
}

// validate is the pure policy check, separated from the admission plumbing
// so it is directly unit-testable.
func validate(ctx context.Context, c client.Client, gs *gitsecretv1alpha1.GitSecret) error {
	// 1. spec.recipients must agree with the wrapped blob -- promotes the
	//    controller's reconcile-time warning (sealer.VerifyRecipients) to a
	//    hard admission reject.
	if err := verifyRecipients(gs.Spec); err != nil {
		return fmt.Errorf("spec.recipients does not match encryptedKey: %w", err)
	}

	// 2. If the namespace declares required recipients, every one must be
	//    present in spec.recipients.
	required, err := requiredRecipients(ctx, c, gs.Namespace)
	if err != nil {
		return err
	}
	if len(required) == 0 {
		return nil
	}
	have := map[string]bool{}
	for _, r := range gs.Spec.Recipients {
		have[strings.ToUpper(r)] = true
	}
	var missing []string
	for _, r := range required {
		if !have[strings.ToUpper(r)] {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("namespace %q requires recipient(s) missing from spec.recipients: %s",
			gs.Namespace, strings.Join(missing, ", "))
	}
	return nil
}

func requiredRecipients(ctx context.Context, c client.Client, namespace string) ([]string, error) {
	if c == nil {
		return nil, nil
	}
	var ns corev1.Namespace
	if err := c.Get(ctx, types.NamespacedName{Name: namespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("look up namespace %q: %w", namespace, err)
	}
	raw := strings.TrimSpace(ns.Annotations[RequiredRecipientsAnnotation])
	if raw == "" {
		return nil, nil
	}
	var out []string
	for _, f := range strings.Split(raw, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out, nil
}
