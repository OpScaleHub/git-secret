# keyfold-controller

Deploys the controller for the `GitSecret` CRD (`api/v1alpha1`): reconciles
GPG-wrapped ciphertext carried inline in a `GitSecret` object into a plain
Kubernetes `Secret` — no repo clone, no SSH transport, no network hop in
the decrypt path. See the [`keyfold` reference](../../docs/reference/keyfold.md)
for the full reference, including `keyfold` and `--rewrap`.

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
  "keyfold-controller <controller@yourcluster>" default default never
gpg --list-secret-keys --with-colons   # grab the fingerprint

gpg --export-secret-keys --armor <fingerprint> > private.asc
kubectl create secret generic keyfold-controller-gpg \
  --from-file=private.asc=./private.asc
rm private.asc
```

Every `GitSecret` this controller should be able to decrypt needs to be
sealed with that same fingerprint as one of its `--recipient`s.

## Install

```bash
helm install keyfold-controller \
  oci://ghcr.io/opscalehub/charts/keyfold-controller \
  --set gpgPrivateKey.existingSecret=keyfold-controller-gpg
```

With that release name every resource is named `keyfold-controller`
(`-webhook`, `-pubkey`, `-seal-ui`, `-metrics` for the Services). A release
name that doesn't contain the chart name gets it appended
(`<release>-keyfold-controller`).

## Pod Security

Every pod this chart creates meets the Kubernetes Pod Security
**`restricted`** profile out of the box (non-root, no privilege escalation,
all capabilities dropped, read-only root filesystem, `RuntimeDefault`
seccomp), so it installs into a namespace labelled
`pod-security.kubernetes.io/enforce: restricted`.

## Cluster-scoped by default

The controller watches `GitSecret` objects in every namespace, and this
chart's RBAC (a `ClusterRole`/`ClusterRoleBinding`) matches that — it can
read/write `Secret`s cluster-wide, scoped only by which `GitSecret`
objects it's actually given (each one is sealed to a specific set of
recipients; a `GitSecret` the controller's key can't open is left alone,
its `status` reporting the failure instead of touching any `Secret`).
To confine it, list the namespaces in `watchNamespaces`: the chart then
grants `Secret`/`GitSecret` access through a `Role`/`RoleBinding` in each
listed namespace instead of cluster-wide, and passes `--watch-namespaces` so
the controller's cache matches.

## Recipient rotation

Adding or removing a recipient (a human, a second controller replica in
another cluster, a backup identity) never re-encrypts a `GitSecret`'s
values — only its wrapped content key:

```bash
keyfold --rewrap gitsecret.yaml \
  --recipient <controller-fpr> --recipient <new-recipient-fpr> > gitsecret.new.yaml
mv gitsecret.new.yaml gitsecret.yaml   # never redirect onto the input: the shell truncates it first
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
`keyfold.opscalehub.io/required-recipients` annotation on the
`Namespace`. The controller generates its own self-signed serving
certificate at startup and patches the CA into the
`ValidatingWebhookConfiguration` — **no cert-manager required**.

This adds RBAC for `namespaces` (get) and
`validatingwebhookconfigurations` (get/update), a webhook `Service`, and
a `POD_NAMESPACE` env via the downward API. Leave `webhook.failurePolicy`
at `Fail`. See `docs/architecture/admission-webhook.md`.

## Publishing the controller's public key

Whoever seals `GitSecret`s to this controller needs its public key. Two
optional ways to expose it:

- `servePubKey.enabled` — the controller serves `GET /pubkey` on a
  ClusterIP `Service` (fingerprint on line 1, then the armored key).
- `publishPublicKey.enabled` — a post-install/upgrade hook `Job` writes
  the fingerprint + public key into a `ConfigMap`
  (`publishPublicKey.configMapName`, default `keyfold-controller-pubkey`),
  which is nicer for GitOps / `kubectl get`.

Both are off by default; use either or both. See
`docs/architecture/keyring.md`.

## Metrics

`/metrics` is served over HTTPS on `metrics.port` (default 8443) behind the
apiserver's own authentication and authorization: each scrape's bearer
token goes through a `TokenReview`, and its user must be allowed `get` on
the `/metrics` non-resource URL. The chart creates a
`<fullname>-metrics-reader` `ClusterRole` for that — bind it to your
scraper:

```bash
kubectl create clusterrolebinding prometheus-keyfold-metrics \
  --clusterrole=keyfold-controller-metrics-reader \
  --serviceaccount=monitoring:prometheus
```

The serving certificate is self-signed, so configure the scraper with
`insecure_skip_verify` (or `tls_config.insecureSkipVerify` in a
`ServiceMonitor`). `metrics.secure: false` restores the plain,
unauthenticated HTTP endpoint.

## Sealing web form (`sealUi.enabled`)

Runs `keyfold ui` in-cluster from the same image: a public-key-only
web form for producing `GitSecret` manifests. It has
`automountServiceAccountToken: false` -- it cannot reach the API -- never
decrypts, and never persists. Reach it with `kubectl port-forward
svc/<fullname>-seal-ui 8080:80`; there is no Ingress.

`sealUi.keyringConfigMap` is **required**: it names a `ConfigMap` with a
`keyring.yaml` (fingerprint + role + armored `publicKey` for every entry).
In-cluster there is no operator GPG keyring, so these are the only keys the
UI can seal to; the chart refuses to render without it and the UI refuses
to start if any entry lacks its `publicKey`. See
`docs/architecture/sealing-console.md`.
