# Changelog

## Unreleased

### Controller hardening (Beta → GA, #77)

- **Reconcile no longer self-triggers.** The reconciler wrote `status.lastSyncTime`
  on every pass; that write returned through its own watch and re-enqueued the
  object, so a steady-state `GitSecret` reconciled forever. Status is now written
  only when a field other than `lastSyncTime` changes.
- **Webhook now requires `replicaCount: 1`.** The serving cert is per-pod and the
  `ValidatingWebhookConfiguration.caBundle` holds one CA; the chart refuses
  `webhook.enabled` with more than one replica, and the CA injector is
  leader-gated. Reconcile HA via leader election is unchanged.
- **Tighter controller RBAC.** Dropped unused verbs (`secrets: delete`,
  `gitsecrets: update/patch`); scoped `validatingwebhookconfigurations`
  `update/patch` to the controller's own config by name. New `watchNamespaces`
  value confines the cache and Secret RBAC to a fixed namespace list
  (`--watch-namespaces`).
- New [UPGRADING.md](UPGRADING.md): the `v1alpha1` "additive only" compatibility
  policy.

### Deprecations

- **`git-secret-server` (the ESO webhook bridge) is now explicitly deprecated.**
  It is superseded by the native `GitSecret` CRD + `git-secret-controller`. The
  binary, image, and Helm chart are still published so existing External Secrets
  Operator users are not broken, and it receives security fixes only — no new
  features. New deployments should use the `GitSecret` CRD. The chart is marked
  `deprecated: true`.

### Docs

- Landing page: corrected the hook-skip note — only `SECRETIZE_SKIP_HOOKS=1`
  skips hooks; the ambient `CI` variable deliberately does not (it previously
  implied `CI=1` would).
- `disaster-recovery.md` / `recipient-lifecycle.md`: clarified that CRD
  `recipients remove` performs a *rewrap* (same content key, `encryptedData`
  untouched), not a content-key rotation — a removed recipient who cached the
  content key can still decrypt values that have not since changed. The CLI
  `git secret removeuser` still forces a full `rotate-keys` and is unchanged.

## v0.9.0 — 2026-08-28

### `git-secret-seal ui`

- A public-key-only web form for producing `GitSecret` manifests, for people who
  would rather not drive the CLI. It never decrypts, never touches the Kubernetes
  API, and never persists anything — the output is a manifest you review and
  `kubectl apply` yourself.
  - Run locally: `git-secret-seal ui` (binds `127.0.0.1:8765`).
  - Run in-cluster: chart `sealUi.enabled` deploys it (`automountServiceAccountToken:
    false` — it cannot reach the API), reached only by `kubectl port-forward`.
  - `--keyring FILE|URL` pre-fills the recipient picker; keyring entries may carry
    an armored `publicKey` so in-cluster sealing needs no operator keyring.
- The controller image now bundles the `git-secret-seal` binary.
- `git-secret-seal ui` sets up its own isolated GNUPGHOME when the keyring
  carries public keys, so the in-cluster deployment works on a read-only root
  filesystem.

### Hardening (pre-freeze audit)

- `git-secret-seal ui` bounds a single `/api/seal` request (key count + total
  value bytes) to the same limits the sealer enforces per object.
- `gpgutil.CountRecipients` — the admission-webhook recipient check, which parses
  the object's attacker-controlled `encryptedKey` — runs under a 5s timeout; the
  `ValidatingWebhookConfiguration` gets `timeoutSeconds: 10`.
- `--keyring` URL fetches stop after 3 redirects.

### Docs

- `docs/architecture/admission-webhook.md` records the live end-to-end
  verification of the validating webhook against a real cluster (2026-08-28).

## v0.8.0 — 2026-08-27 — security hardening (#38–#58)

A backlog reset focused on making the `GitSecret` CRD a defensible
production-grade integration. No breaking changes; additive CRD fields only
(`spec.recipients`, `spec.target.adopt`, `status.recipients` /
`status.recipientCount` / `status.sourceRevision`).

### Security & docs

- **Threat model** (`docs/security/threat-model.md`), **design rationale**
  (recovered ADR reasoning), **disaster-recovery runbooks**, **recipient &
  key lifecycle**, **multi-cluster** and **cluster keyring** notes, and
  `SECURITY.md`. The repo previously had no security documentation.
- Recovery scenarios A–E are covered by tests in
  `internal/sealer/recovery_test.go` — the loss-vs-compromise distinction is
  explicit and asserted.

### Controller

- Refuses to adopt/clobber a `Secret` it does not own — reports a
  `TargetConflict` condition instead. Opt in per target with
  `spec.target.adopt: true`.
- Bounds on `spec.encryptedData` (≤1024 entries via CRD `maxProperties`;
  ≤1 MiB per encoded value) so a malformed object can't force unbounded
  decryption.
- Mirrors the recipient set into `status.recipients` / `status.recipientCount`
  (new `Recipients` printer column); logs a warning if `spec.recipients` and
  the wrapped blob disagree.

### `git-secret-seal`

- `spec.recipients` is written into every sealed manifest.
- `recipients list|add|remove` subcommand — mutate the recipient set of an
  existing manifest without retyping it; refuses to drop the last recipient or
  the last `recovery`-role recipient without `--force`.
- Recipient roles (`human` / `controller` / `recovery` / `deprecated`) recorded
  in the `git-secret.opscalehub.io/recipient-roles` annotation.
- `--keyring FILE` resolves recipients (and roles) from a committed keyring file.
  `--keyring` also accepts an `http(s)://` URL, and keyring entries may carry an
  armored `publicKey`.
- `git-secret-seal ui` — a public-key-only web form for producing GitSecret
  manifests. Never decrypts, never touches the cluster API, never persists. Run
  locally (`127.0.0.1:8765`) or in-cluster via the chart's `sealUi.enabled`
  (reached by `kubectl port-forward`).

### `git-secret-controller`

- `--print-public-key` — import the configured key and print its fingerprint +
  armored public key, for handing to whoever seals to this controller.
- `--serve-pubkey-address` — serve `GET /pubkey` (fingerprint + armored public
  key) for discovery. Chart: `servePubKey.enabled`.
- `--publish-public-key-configmap` — one-shot: upsert a ConfigMap with the
  fingerprint + public key, then exit. Chart: `publishPublicKey.enabled` runs it
  as a post-install/upgrade hook Job.
- `--enable-webhook` — an optional validating admission webhook for `GitSecret`
  that rejects a `spec.recipients` / `encryptedKey` mismatch and enforces a
  per-namespace required-recipient set. Self-signed cert managed by the
  controller, no cert-manager. Chart: `webhook.enabled`.

### CLI

- `git secret init` prints a nudge when it falls back to the `file` backend,
  which is incompatible with automated consumers.

### Provenance

- `git-secret-seal` stamps `git-secret.opscalehub.io/source-revision` /
  `source-repo` from the current Git HEAD (override `--source-revision`, disable
  `--no-provenance`); the controller mirrors the revision to
  `status.sourceRevision` (a `Revision` printer column).
