# Changelog

## Unreleased — security hardening (#38–#48)

A backlog reset focused on making the `GitSecret` CRD a defensible
production-grade integration. No breaking changes; one additive CRD field
(`spec.recipients`) and one additive nested field (`spec.target.adopt`).

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
  `--keyring` also accepts an `http(s)://` URL.

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
