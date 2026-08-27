# git-secret-controller

Deploys the controller for the `GitSecret` CRD (`api/v1alpha1`): reconciles
GPG-wrapped ciphertext carried inline in a `GitSecret` object into a plain
Kubernetes `Secret` — no repo clone, no SSH transport, no network hop in
the decrypt path. See the main [README](../../README.md#gitsecret-crd-git-secret-controller)
for the full reference, including `git-secret-seal` and `--rewrap`.

This chart installs the CRD (`crds/gitsecret.yaml`) alongside the
controller. Helm never upgrades or deletes CRDs automatically on
`helm upgrade`/`helm uninstall` — if the CRD schema changes in a future
chart version, apply the updated CRD yourself (`kubectl apply -f
crds/gitsecret.yaml` from the new chart version) before upgrading.

## Before installing

This chart never accepts secret material in `values.yaml` — only a
reference to a `Secret` you create yourself, out-of-band. Give the
controller its own dedicated GPG identity — never reuse a human's key —
and hand it only the private half:

```bash
gpg --batch --passphrase '' --quick-generate-key \
  "git-secret-controller <controller@yourcluster>" default default never
gpg --list-secret-keys --with-colons   # grab the fingerprint

gpg --export-secret-keys --armor <fingerprint> > private.asc
kubectl create secret generic git-secret-controller-gpg \
  --from-file=private.asc=./private.asc
rm private.asc
```

Every `GitSecret` this controller should be able to decrypt needs to be
sealed with that same fingerprint as one of its `--recipient`s.

## Install

```bash
helm install git-secret-controller \
  oci://ghcr.io/opscalehub/charts/git-secret-controller \
  --set gpgPrivateKey.existingSecret=git-secret-controller-gpg
```

## Cluster-scoped by default

The controller watches `GitSecret` objects in every namespace, and this
chart's RBAC (a `ClusterRole`/`ClusterRoleBinding`) matches that — it can
read/write `Secret`s cluster-wide, scoped only by which `GitSecret`
objects it's actually given (each one is sealed to a specific set of
recipients; a `GitSecret` the controller's key can't open is left alone,
its `status` reporting the failure instead of touching any `Secret`).
There's no per-namespace restriction wired up in this chart today — if
your cluster needs one, replace `templates/rbac.yaml`'s `ClusterRole`/
`ClusterRoleBinding` with a `Role`/`RoleBinding` per namespace.

## Recipient rotation

Adding or removing a recipient (a human, a second controller replica in
another cluster, a backup identity) never re-encrypts a `GitSecret`'s
values — only its wrapped content key:

```bash
git-secret-seal --rewrap gitsecret.yaml \
  --recipient <controller-fpr> --recipient <new-recipient-fpr> > gitsecret.yaml
kubectl apply -f gitsecret.yaml
```

## Multiple replicas

Set `replicaCount` above 1 for availability; `leaderElection.enabled`
(default `true`) is what keeps only one replica actually reconciling at a
time — it's safe to leave enabled even at `replicaCount: 1`.

## Validating admission webhook

`webhook.enabled: true` makes the controller also serve a validating
admission webhook for `GitSecret` objects. It rejects a `GitSecret` whose
`spec.recipients` count disagrees with its `encryptedKey`, and enforces a
per-namespace required-recipient set via the
`git-secret.opscalehub.io/required-recipients` annotation on the
`Namespace`. The controller generates its own self-signed serving
certificate at startup and patches the CA into the
`ValidatingWebhookConfiguration` — **no cert-manager required**.

This adds RBAC for `namespaces` (get) and
`validatingwebhookconfigurations` (get/update), a webhook `Service`, and
a `POD_NAMESPACE` env via the downward API. Leave `webhook.failurePolicy`
at `Fail`. See `docs/architecture/admission-webhook.md`.
