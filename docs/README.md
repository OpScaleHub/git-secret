# Documentation

## Security

- [threat-model.md](security/threat-model.md) — assets, trust boundaries, threats
  (key *loss* vs *compromise*), invariants, non-goals.
- [design-rationale.md](security/design-rationale.md) — why the architecture looks
  the way it does; the four integration designs that led to the `GitSecret` CRD.
- [disaster-recovery.md](security/disaster-recovery.md) — operator runbooks for
  controller loss, cluster loss, key loss, key compromise.
- [recipient-lifecycle.md](security/recipient-lifecycle.md) — recipient roles,
  rotation workflows, and what removing a recipient does and does not undo.

## Architecture

- [overview.md](architecture/overview.md) — ASCII diagrams: seal → apply →
  reconcile, the two-layer envelope, the recovery model.
- [multi-cluster.md](architecture/multi-cluster.md) — one encrypted repo,
  per-cluster controller identities, per-environment recipient sets.
- [keyring.md](architecture/keyring.md) — `--print-public-key`,
  `git-secret-seal --keyring`, discoverable recipient public keys.
- [admission-webhook.md](architecture/admission-webhook.md) — optional validating
  webhook enforcing `spec.recipients` and per-namespace required recipients.
- [provenance.md](architecture/provenance.md) — recording which Git revision
  produced a Secret.
- [sealing-console.md](architecture/sealing-console.md) — feasibility analysis for
  a web sealing UI (not scheduled).

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
