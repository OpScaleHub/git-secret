# ADR-0006 — Admission webhook: self-signed, single replica, never decrypts

- Status: **Accepted** (webhook since v0.8; no-decrypt fix in the Keyfold release)

## Context

An optional validating webhook enforces two policies: the declared recipient
count matches the wrapped key, and a Namespace's required recipients are
present. Webhooks usually pull in cert-manager, and run on every write.

## Decision

- The controller mints a **self-signed CA and serving certificate at startup**
  and patches the CA into its `ValidatingWebhookConfiguration` (leader-gated).
  No cert-manager.
- Consequently the webhook requires **one replica**; the chart refuses
  `webhook.enabled` with `replicaCount > 1`.
- The webhook reads only packet headers (`gpg --list-only --list-packets`): no
  private-key operation on the admission path, same result whether or not the
  object is wrapped to this cluster.
- `failurePolicy: Fail` — non-conforming objects are blocked.

## Consequences

- One less dependency; a brief window after install where writes are rejected
  until the CA is injected (the safe direction).
- Multi-replica webhook HA would need a shared certificate (cert-manager) — a
  future option, not built.
- The recipient check is a count, not per-fingerprint authentication.
