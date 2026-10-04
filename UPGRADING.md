# Upgrading git-secret

This document is the compatibility contract. It covers the `GitSecret` CRD +
`git-secret-controller`; the CLI / Git-hook side is versioned by the same tags but
has no cluster state to migrate.

## Versioning

Releases are `vMAJOR.MINOR.PATCH`. The project is pre-1.0, so MINOR bumps may
carry behaviour changes — each one is called out in [CHANGELOG.md](CHANGELOG.md).
The Helm chart version tracks the release tag; the controller image and chart for
a given tag are built and tested together and are expected to be deployed
together.

## The `GitSecret` API

The CRD has one version, `v1alpha1`, and it is both the served and the stored
version. There is **no conversion webhook** and none is planned while there is a
single version.

**Compatibility policy for `v1alpha1`:**

- Changes within `v1alpha1` are **additive only** — new optional `spec` / `status`
  fields, new printer columns, relaxed validation. An object written by an older
  `git-secret-seal` keeps reconciling unchanged after a controller upgrade.
- An existing field's meaning, type, or default will **not** change under
  `v1alpha1`. A change that would require one is introduced as a new version
  (`v1alpha2` / `v1`) with a conversion path and a migration note here — it will
  not be a silent break of `v1alpha1`.
- `spec.encryptedData` / `spec.encryptedKey` are opaque ciphertext produced by
  `git-secret-seal`; their envelope format is versioned independently inside the
  blob (`crypto/envelope.go`) and old envelopes stay decryptable — see the
  "cipher agility" tests in `crypto/`.

**When a new API version is introduced**, this document will gain a section with:
the field-by-field mapping, whether the conversion is automatic (conversion
webhook) or a one-time re-seal, and the release in which `v1alpha1` stops being
served.

## Upgrade procedure

1. `helm upgrade` the chart. The CRD ships with the chart under `crds/`; Helm
   installs a CRD but does **not** upgrade one it already owns — apply
   `charts/git-secret-controller/crds/gitsecret.yaml` (or
   `config/crd/bases/...`) yourself when a release changes it (the CHANGELOG
   says when).
2. The controller re-imports its GPG key and re-reconciles every `GitSecret` on
   start. Target Secrets are owned objects and are re-created if missing.
3. If you changed `webhook.enabled`, note it requires `replicaCount: 1` (see
   [docs/architecture/admission-webhook.md](docs/architecture/admission-webhook.md)).

## Upgrading to the release after v0.10.0 (chart hardening, #106)

Four chart changes, one of which needs a manual step for some installs:

- **Resource names.** A release name that already contains the chart name is
  no longer doubled: `helm install git-secret-controller …` now yields
  `git-secret-controller` (and `-webhook`, `-pubkey`, `-seal-ui`, `-metrics`)
  instead of `git-secret-controller-git-secret-controller-*`. Helm replaces
  the renamed objects on upgrade; nothing to do. Anything *outside* the chart
  that referenced the old names (a `ServiceMonitor`, a `NetworkPolicy`, a
  port-forward script, a `ClusterRoleBinding` to the ClusterRole) must be
  updated.
- **Controller selector.** The controller's pods now carry
  `app.kubernetes.io/component: controller`, and its Deployment and Services
  select on it (so they no longer also match the seal-UI or publish-Job
  pods). A Deployment's selector is immutable, so **if your release name does
  not contain `git-secret-controller`** (the Deployment keeps its name), delete
  it before upgrading:

  ```bash
  kubectl -n <ns> delete deployment <release>-git-secret-controller
  helm upgrade <release> … 
  ```

  The target `Secret`s are untouched; reconciliation pauses until the new pod
  is ready. With `webhook.enabled` and `failurePolicy: Fail`, `GitSecret`
  writes are rejected during that gap — schedule it accordingly. The seal-UI
  Deployment is unaffected (its selector did not change).
- **Metrics are authenticated by default** (`metrics.secure: true`): HTTPS with
  a self-signed cert behind `TokenReview`/`SubjectAccessReview`. Bind the new
  `<fullname>-metrics-reader` ClusterRole to your scraper and switch it to
  HTTPS, or set `metrics.secure: false` to keep the old plain endpoint.
- **`sealUi.enabled` requires `sealUi.keyringConfigMap`** whose entries all
  carry a `publicKey`. Without one the in-cluster UI could never seal (it had no
  keys and a read-only filesystem); the chart now says so at render time.

Pods now also set `seccompProfile: RuntimeDefault`, so the chart installs into
Pod Security `restricted` namespaces.

## Downgrade

Additive-only means a downgrade is safe for objects that do not use fields the
older controller lacks: it ignores unknown `status` fields, and an unknown
optional `spec` field set by a newer `git-secret-seal` is preserved by the
apiserver but not acted on. Re-seal with the matching `git-secret-seal` version
if in doubt.
