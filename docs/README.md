# Documentation

Start with **[concepts.md](concepts.md)** — the model, who can do what, and what
each operation (rewrap, rekey, set, secret rotation) changes, plus the glossary.

## Get started

- [Kubernetes quickstart](getting-started/quickstart.md) — install, seal to
  three recipients, recover with no cluster. Ten minutes.
- [Git plugin](getting-started/git-plugin.md) — encrypted files in a
  repository, no Kubernetes needed.

## Operate

- [Multi-cluster](architecture/multi-cluster.md) — one repository, per-cluster
  controller identities; add, replace or retire a cluster.
- [Recipient & key lifecycle](security/recipient-lifecycle.md) — roles, adding
  and removing people, offboarding, key expiry.
- [Disaster recovery](security/disaster-recovery.md) — runbooks: controller,
  cluster or key lost; key compromised; no cluster at all.
- [Troubleshooting](guides/troubleshooting.md) — real error messages and fixes.
- [Upgrading](../UPGRADING.md) — compatibility contract and the migration from
  the pre-rename names.

## Reference

- [`keyfold` and the controller](reference/keyfold.md) — every command, the
  `GitSecret` object, controller behaviour.
- [`git keyfold`](reference/git-keyfold.md) — commands, `.keyfold.yml`, key
  backends, how the hooks work.
- [`kubectl keyfold`](reference/kubectl-keyfold.md) — encrypted values inside a
  plain `Secret` manifest.
- [Helm chart](../charts/keyfold/README.md) — values, Pod Security, metrics,
  webhook, sealing UI.
- [Keyring files](architecture/keyring.md) — per-environment recipient lists,
  embedded public keys, publishing a controller's key.
- [Provenance](architecture/provenance.md) — which commit produced a `Secret`.
- [Admission webhook](architecture/admission-webhook.md) and
  [sealing console](architecture/sealing-console.md).

## Design and security

- [Architecture overview](architecture/overview.md) — diagrams of the seal →
  apply → reconcile flow, the envelope, and recovery.
- [Threat model](security/threat-model.md) — assets, trust boundaries, threats,
  invariants, and what is deliberately out of scope.
- [Decision records](adr/) — the settled decisions, one page each.
- [Design history](security/design-rationale.md) — how the design got here.
- [Reporting a vulnerability](../SECURITY.md).
