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

## Downgrade

Additive-only means a downgrade is safe for objects that do not use fields the
older controller lacks: it ignores unknown `status` fields, and an unknown
optional `spec` field set by a newer `git-secret-seal` is preserved by the
apiserver but not acted on. Re-seal with the matching `git-secret-seal` version
if in doubt.
