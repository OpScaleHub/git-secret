# Upgrading Keyfold

This document is the compatibility contract. It covers the `GitSecret` CRD +
`keyfold-controller`; the CLI / Git-hook side is versioned by the same tags but
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
  `keyfold` keeps reconciling unchanged after a controller upgrade.
- An existing field's meaning, type, or default will **not** change under
  `v1alpha1`. A change that would require one is introduced as a new version
  (`v1alpha2` / `v1`) with a conversion path and a migration note here — it will
  not be a silent break of `v1alpha1`.
- `spec.encryptedData` / `spec.encryptedKey` are opaque ciphertext produced by
  `keyfold`; their envelope format is versioned independently inside the
  blob (`crypto/envelope.go`) and old envelopes stay decryptable — see the
  "cipher agility" tests in `crypto/`.

**When a new API version is introduced**, this document will gain a section with:
the field-by-field mapping, whether the conversion is automatic (conversion
webhook) or a one-time re-seal, and the release in which `v1alpha1` stops being
served.

## Upgrade procedure

1. `helm upgrade` the chart. The CRD ships with the chart under `crds/`; Helm
   installs a CRD but does **not** upgrade one it already owns — apply
   `charts/keyfold/crds/gitsecret.yaml` (or
   `config/crd/bases/...`) yourself when a release changes it (the CHANGELOG
   says when).
2. The controller re-imports its GPG key and re-reconciles every `GitSecret` on
   start. Target Secrets are owned objects and are re-created if missing.
3. If you changed `webhook.enabled`, note it requires `replicaCount: 1` (see
   [docs/architecture/admission-webhook.md](docs/architecture/admission-webhook.md)).

## Upgrading from v0.10.x: the Keyfold release

The project is renamed from **git-secret** to **Keyfold**
([ADR-0001](docs/adr/0001-product-name.md)). This is the one release that
changes names; every ciphertext stays valid and **nothing is re-sealed**.

### What changes

| | v0.10.x | now |
|---|---|---|
| Sealing CLI | `git-secret-seal` | `keyfold` (`keyfold seal`, `recipients`, `ui`, `migrate`) |
| Git plugin | `git-secret` → `git secret …` | `git-keyfold` → `git keyfold …` |
| kubectl plugin | `kubectl-secret` → `kubectl secret …` | `kubectl-keyfold` → `kubectl keyfold …` |
| Controller image | `ghcr.io/opscalehub/git-secret-controller` | `ghcr.io/opscalehub/keyfold-controller` |
| Helm chart | `oci://ghcr.io/opscalehub/charts/git-secret-controller` | `oci://ghcr.io/opscalehub/charts/keyfold` |
| CRD API group | `git-secret.opscalehub.io/v1alpha1` | `keyfold.opscalehub.io/v1alpha1` (kind `GitSecret` unchanged) |
| Annotations | `git-secret.opscalehub.io/*` | `keyfold.opscalehub.io/*` — old keys still **read** |
| Repo config | `.repo-enc.yml`, keys under `.repo-enc/` | new repos: `.keyfold.yml`, `.keyfold/`; existing repos keep the old names, untouched |
| Env vars | `SECRETIZE_SKIP_HOOKS`, `REPO_ENC_CONFIG_DIR` | `KEYFOLD_SKIP_HOOKS`, `KEYFOLD_CONFIG_DIR` — old names still honoured |
| `git-secret-server` | deprecated | **removed** (v0.10.0 is its last release) |

Never changed: the `RENC` envelope, the `repo-enc:v1:` per-value prefix, the
authenticated-data layouts, the wrapped-key format.

### CLI and Git hooks (each repository)

Install the new binaries, then run `git keyfold init` once in each repository.
Installed hooks call the binary by name, so pre-rename hooks (which exec
`git-secret`) fail — closed, blocking commits and pushes — until `init`
rewrites them; `init` recognises and replaces them rather than chaining them.
Your config, key and history are not touched. Renaming `.repo-enc.yml` to
`.keyfold.yml` is optional (`git mv`); keep `key_source` as it is.

### Cluster: move objects to the new API group

A new API group is a new CRD, so each `GitSecret` moves once. A GitSecret's
ciphertext is bound to `namespace/name/key`, never to the group, so moving it
is a text rewrite — no recipient needs to be present and no value is
re-sealed. The target `Secret`s stay in place throughout.

1. **Rewrite the manifests** in Git (apiVersion and annotation keys only;
   comments and ciphertext untouched; idempotent):

   ```bash
   keyfold migrate -f deploy/ --dry-run   # review
   keyfold migrate -f deploy/
   ```

   Namespaces carrying the required-recipients annotation are migrated too.
2. **Stop the old controller**, leaving its CRD and objects in place:
   `helm uninstall git-secret-controller -n <ns>` (Helm does not delete CRDs).
3. **Install the new chart** with the same GPG key Secret:

   ```bash
   helm install keyfold oci://ghcr.io/opscalehub/charts/keyfold \
     --namespace <ns> --set gpgPrivateKey.existingSecret=<existing-key-secret>
   ```
4. **Apply the migrated manifests** (or let your GitOps tool sync them). For
   each object, the new controller finds the target `Secret` still controlled
   by the pre-rename `GitSecret` of the same name, takes it over, and
   reconciles it — no `spec.target.adopt` needed. Only that exact predecessor
   (same namespace, same name, kind `GitSecret`, old group) is adopted.
5. **Remove the old objects and CRD** once `kubectl get gitsecrets.keyfold.opscalehub.io -A`
   shows them `Ready`:

   ```bash
   kubectl delete crd gitsecrets.git-secret.opscalehub.io
   ```

   The `Secret`s no longer reference the old objects, so nothing is
   garbage-collected.

Between steps 2 and 4 nothing reconciles; existing `Secret`s keep serving
workloads, and only changes made in that window wait for step 4.

### Chart changes that come with this release

- Resource names are no longer doubled: release `keyfold` yields `keyfold`,
  `keyfold-webhook`, `keyfold-pubkey`, `keyfold-seal-ui`, `keyfold-metrics`.
  Update anything outside the chart that referenced old names (a
  `ServiceMonitor`, `NetworkPolicy`, scripts).
- Pods meet Pod Security `restricted` (`seccompProfile: RuntimeDefault`).
- Controller pods are selected by `app.kubernetes.io/component: controller`.
- **Metrics are authenticated by default** (`metrics.secure: true`): HTTPS
  (self-signed) behind `TokenReview` + `SubjectAccessReview`. Bind the
  `keyfold-metrics-reader` ClusterRole to your scraper, or set
  `metrics.secure: false`.
- `sealUi.enabled` requires `sealUi.keyringConfigMap`, every entry carrying
  its `publicKey`.
- The public-key ConfigMap default is `keyfold-pubkey`
  (`publishPublicKey.configMapName`).

### `git-secret-server` users

Removed. Seal each secret as a `GitSecret` (`keyfold seal`, multi-recipient,
with the controller's fingerprint among the recipients), apply it with
`spec.target.adopt: true` to take over the `Secret` the `ExternalSecret`
created, then delete the `ExternalSecret`. v0.10.0 artifacts remain
available but receive no fixes.

## Downgrade

Additive-only means a downgrade is safe for objects that do not use fields the
older controller lacks: it ignores unknown `status` fields, and an unknown
optional `spec` field set by a newer `keyfold` is preserved by the
apiserver but not acted on. Re-seal with the matching `keyfold` version
if in doubt.
