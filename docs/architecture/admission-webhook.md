# Validating admission webhook

Optional. When enabled, `keyfold-controller` also serves a validating
admission webhook for `GitSecret` objects, turning two things that were
conventions into enforced policy (threat-model T11 / invariant #9).

## What it enforces

On every `CREATE` / `UPDATE` of a `GitSecret`:

1. **`spec.recipients` must agree with `encryptedKey`.** The count of fingerprints
   in `spec.recipients` must equal the number of public-key recipients the
   wrapped blob actually has (`sealer.VerifyRecipients`). Without the webhook this
   is only a controller log warning; with it, a mismatch is rejected at admission.
2. **Per-namespace required recipients.** If the object's Namespace carries
   `keyfold.opscalehub.io/required-recipients: "<fpr>,<fpr>"`, every listed
   fingerprint must be present in `spec.recipients` — e.g. to force an offline
   recovery key into every `GitSecret` in `prod`.

It does **not** decrypt, and it is not on the reconcile path — it only gates
what gets written to the API. The recipient count is read from the wrapped
key's packet headers (`gpg --list-only --list-packets`): no private-key
operation, no gpg-agent, and it works the same whether or not this
controller's own key is among the recipients — so an object sealed for another
cluster, or re-applied during recovery before its rewrap, is admitted on the
same rules and then reported `UnsealFailed` by the controller rather than
rejected at admission.

## Certificates — no cert-manager

The controller generates its own self-signed CA + serving certificate at startup
(valid for `<service>.<namespace>.svc`), writes the serving cert to a tmpfs dir
for the webhook server, and patches the CA into the
`ValidatingWebhookConfiguration`'s `clientConfig.caBundle` via the API. The CA is
regenerated on every restart and re-injected, so there is nothing to rotate and
no external dependency.

Trade-off: on a fresh install there is a brief window between the
`ValidatingWebhookConfiguration` being created (empty `caBundle`) and the
controller injecting the CA, during which — with `failurePolicy: Fail` —
`GitSecret` writes are rejected. That is the safe direction, and it clears within
seconds of the controller becoming ready.

**Requires `replicaCount: 1`.** The serving cert is per-pod and the
`ValidatingWebhookConfiguration.caBundle` holds exactly one CA — the elected
leader injects its own. Run more than one replica and the apiserver load-balances
admission calls across pods whose certs the published CA does not vouch for, so
`failurePolicy: Fail` rejects a fraction of `GitSecret` writes. The CA injector is
leader-gated (`internal/webhook.caBundleInjector`) so a mis-scaled deployment is
not also a write-storm on the cluster-scoped config, and the chart refuses
`webhook.enabled` with `replicaCount > 1` outright. Multi-replica webhook HA needs
a shared cert (cert-manager); reconcile HA via leader election is unaffected and
does not need the webhook.

## Enabling it

Helm:

```yaml
# values.yaml
webhook:
  enabled: true
  failurePolicy: Fail   # leave this; the point is to block non-conforming objects
```

This adds the `--enable-webhook` args, a `POD_NAMESPACE` env (downward API), the
webhook `Service`, the `ValidatingWebhookConfiguration`, and RBAC for
`namespaces` (get) and `validatingwebhookconfigurations` (get/update).

Manually: run the controller with `--enable-webhook --webhook-service <svc>
--webhook-config-name <name>` and `POD_NAMESPACE` set; create a `Service` on port
443 → container port 9443 and a `ValidatingWebhookConfiguration` pointing at
`/validate-keyfold-opscalehub-io-v1alpha1-gitsecret` with an empty `caBundle`.

## Not covered

Matching against a full keyring file / `ClusterKeyring` object (only the simpler
Namespace-annotation form is implemented), and mutating defaults. Keyring-over-HTTP is covered in [keyring.md](keyring.md).
