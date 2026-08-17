---
title: A native GitSecret CRD/controller, alongside (not replacing) the ESO webhook bridge
tags: [git-secret, adr, kubernetes, crd, controller, external-secrets-operator, security]
---

# ADR-0002: A native `GitSecret` CRD/controller, alongside (not replacing) the ESO webhook bridge

## Status

Accepted. Implemented as `api/v1alpha1`, `internal/controller`, `cmd/git-secret-controller`,
`cmd/git-secret-seal`, `internal/sealer`. Not yet adopted by any production consumer — see
Consequences.

## Context

**In one sentence, for readers who don't have ADR-0001 memorized**: ADR-0001's "no functional
benefit over reusing ESO" reasoning was correct for the case it actually weighed at the time; this
ADR addresses a different case that only became visible after the ESO webhook bridge was built,
deployed to production, and formally security-reviewed. The rest of this section spells out exactly
where the two cases diverge.

ADR-0001 explicitly foreclosed "a bespoke Kubernetes controller (its own CRD, its own reconcile
loop) in place of wrapping ESO," reasoning that ESO already provides the reconcile loop, drift
detection, deletion policy, status/observability, and RBAC scoping a hand-rolled controller would
otherwise have to rebuild for no functional benefit. That reasoning holds for what it was actually
weighing at the time: a controller that reproduces ESO's job — pluggable backends, generic secret
lifecycle management. It does **not** hold for what this ADR is actually about, which only became
visible after `git-secret-server` (the ESO webhook bridge) was built, deployed to a real production
cluster, and formally security-reviewed:

**ESO's provider model assumes a remote key/value store you *query*. `git-secret`'s actual data —
ciphertext — doesn't need a store to query; it can be delivered as inert YAML by whatever already
applies manifests to the cluster (ArgoCD, `kubectl apply`, ...), the same way every other Kubernetes
object gets there.** Wrapping that reality in ESO's Webhook provider forces an architecture ESO's own
model doesn't natively fit:

- Every decrypt request means **cloning the whole repository fresh**, inside the cluster, on every
  ESO refresh interval, for every consumer. The actual payload needed is a handful of already-known
  ciphertext blobs; the clone is pure overhead this design forces, not something the problem itself
  requires.
- That clone step needs its own SSH transport, its own known-hosts trust decision, and — this is the
  concrete finding, not a hypothetical — this project's own formal security review of the deployed
  code confirmed a real gap: `gitutil`'s SSH clone falls back to `StrictHostKeyChecking=accept-new`
  (trust-on-first-use) whenever no `known_hosts` is pinned for a non-GitHub host, and the Helm chart
  has no fail-fast guard forcing an operator to notice they need to pin one. Not currently exploitable
  against `downtime` (GitHub-hosted, built-in pin applies) — but it is a real, live attack surface
  *that a no-clone design does not have at all*, not one this design merely reduces.
- Adopting an **already-existing** Secret through this path needed ESO's `creationPolicy: Merge` /
  `deletionPolicy: Retain` combination specifically to avoid ESO's default `Owner` policy conflicting
  with a Secret it didn't create — a real, working solution, but one that only exists because the
  webhook-bridge path can't itself be the thing that originally created the Secret declaratively.
- Every layer in the path (ArgoCD → ESO `ClusterSecretStore`/`ExternalSecret` → webhook HTTP call →
  fresh clone → decrypt) is a place a sync-wave ordering bug, a CRD-size limit, an auth-Secret label
  requirement, or a retry-exhaustion state can (and, during this project's own production rollout,
  did) stall delivery. None of that complexity is inherent to "decrypt some GPG-wrapped values" — it's
  the cost of routing that through a generic external-store abstraction.

Bitnami's `sealed-secrets` project solves the adjacent problem (arbitrary plaintext → a Secret a
cluster can produce) with a categorically simpler shape: ciphertext lives **inline in a CRD object**,
delivered by the normal manifest-apply path, decrypted by a controller holding the matching private
key — no clone, no query, no separate network hop in the decrypt path at all. `sealed-secrets` itself
has one well-documented real-world weakness worth naming directly rather than glossing over: a single
controller keypair is a single point of failure — lose it, and every already-sealed secret is
permanently unrecoverable, with no independent recovery path. That is *not* an inherent property of
the CRD-inline-ciphertext shape; it's a property of `sealed-secrets`' specific single-recipient
implementation.

## Decision

Add a **`GitSecret` CRD** (`git-secret.opscalehub.io/v1alpha1`) and a controller
(`cmd/git-secret-controller`) that reconciles it into a plain `Secret` — the sealed-secrets shape,
applied to `git-secret`'s existing GPG-backed multi-recipient cryptography instead of copying
`sealed-secrets`' single-keypair design:

- **Ciphertext inline, not cloned.** `spec.encryptedKey` is `git-secret`'s existing GPG-wrapped
  content key (identical mechanism to `keybackend.GPGBackend`); `spec.encryptedData` holds one
  AEAD-sealed value per target key (identical envelope format to whole-file encryption,
  `crypto.Seal`/`crypto.Open`). Reconciling a `GitSecret` never makes a network call, never clones a
  repository, and never needs its own SSH transport or known-hosts trust decision — the entire
  SSH-TOFU finding class doesn't exist on this path, structurally, not just mitigated.
- **Multi-recipient from the start, with a real cheap-rotation story.** `spec.encryptedKey` can be
  wrapped to any number of GPG recipients — the controller's own identity, and independently, any
  number of humans or backup identities — exactly like `keybackend.GPGBackend` already supports for
  whole-repo files. `internal/sealer.Rewrap` re-encrypts *only* `encryptedKey` to a new recipient
  list, leaving every value in `encryptedData` byte-for-byte untouched — proven in
  `TestRewrap_AddsRecipientWithoutTouchingEncryptedData`, including the specific property that
  matters for DR: a recipient added via `Rewrap` can decrypt independently afterward, with no
  involvement from the key that did the rewrapping. Losing the controller's own key is a `Rewrap`
  away from recovery via any other currently-valid recipient — not a permanent loss.
- **`namespace/name/key` bound into the AEAD additional-authenticated-data** for every value
  (`internal/sealer.aad`), proven in `TestUnsealWrongObjectFails`: an entry copied into a different
  `GitSecret`, or a renamed/moved one, fails authentication rather than silently decrypting somewhere
  it wasn't sealed for.
- **`git-secret-seal`**, a `kubeseal`-equivalent CLI: produces a `GitSecret` manifest from
  `--from-literal`/`--from-env-file`/an existing Secret manifest, and rewraps an existing one's
  recipient list via `--rewrap`. Never writes plaintext to disk beyond what the caller already gave
  it.
- **`controller-runtime`-based**, not a hand-rolled watch loop — reusing a mature, widely-deployed
  library (the same one ESO, cert-manager, and `sealed-secrets` itself are built on) for the
  informer/reconcile/leader-election machinery is exactly the "don't rebuild what's already solved"
  principle ADR-0001 applied to ESO's secret-lifecycle machinery; it just applies to a different,
  narrower slice here (K8s controller plumbing, not secret-store abstraction).
- Ownership is `Owner`-style by default (`controllerutil.SetControllerReference`): a `GitSecret`
  created fresh is the sole source of truth for its target `Secret`, deleting one deletes the other —
  deliberately not the ESO webhook path's `Merge`/`Retain` adoption workaround, because this
  controller doesn't have that path's "can't have been the thing that created it" constraint.

This is genuinely tested, not just designed: `internal/sealer` and `internal/controller` have unit
tests running real GPG operations against throwaway keys (no envtest binaries required — the
reconciler is tested against `controller-runtime`'s fake client), and the whole stack — CRD install,
a real `GitSecret` apply, the actual compiled controller binary, a real resulting `Secret` with
correct decrypted values — was proven end-to-end against a disposable local `kind` cluster before
this landed. None of that touched any production cluster or resource.

## Consequences

- **This does not replace `git-secret-server`/the ESO webhook bridge, and does not touch `downtime`'s
  live secrets pipeline.** ADR-0001's ESO-based deployment stays exactly as it is. Adopting the
  `GitSecret` CRD for any real workload — `downtime` included — is a separate, explicitly-gated
  decision for another day, the same discipline used for every other production change in this
  project's history (dry-run before real, throwaway proof before live cutover).
- **Two supported patterns now exist side by side**, and that's a real, permanent cost: the README
  and any future onboarding guidance has to explain when to reach for which. Rough guidance to
  document once this is used for real: prefer `GitSecret` when a workload can tolerate `Owner`-style
  Secret lifecycle (the controller created it, the controller can delete it) and wants zero clone/
  network surface on the decrypt path; keep the ESO webhook bridge where ESO's broader
  ecosystem — multiple backend types behind one abstraction, `dataFrom.extract`-style transforms
  already in use elsewhere in the same cluster — is itself the reason for choosing ESO.
- **A new, separate identity-bootstrap story**: the controller needs its own GPG private key, imported
  at startup exactly like `git-secret-server`'s (`cmd/git-secret-controller` mirrors that startup
  sequence — isolated `GNUPGHOME`, key zeroed from memory after import). Any real deployment needs the
  same durable-backup answer already flagged as outstanding for `git-secret-server-downtime`'s key —
  this doesn't add a new open item, it's the same one, now shared by a second component.
  Multi-recipient sealing directly mitigates the *permanent loss* failure mode either component's
  single key could otherwise represent.
- **Explicitly not done in this pass, and should not be assumed done**: a Helm chart, container image,
  CI/release wiring, and RBAC manifests for `cmd/git-secret-controller` (all straightforward given the
  existing `git-secret-server` chart as a template, but real work, not yet started); a migration
  runbook for converting an ESO-adopted `Secret` to `GitSecret` ownership; and a decision on whether
  `git-secret-controller` and `git-secret-server` should ever run in the same cluster namespace or
  stay fully independent per-consumer choices.
- Nothing here invalidates ADR-0001's separate reasoning about GitHub Secrets (still structurally
  impossible) or a third-party secret store (still an avoidable new dependency). It specifically
  narrows ADR-0001 point 5 — "no functional benefit over reusing ESO" — to the case that reasoning
  actually applies to: reproducing ESO's own job. Delivering inline ciphertext through the existing
  manifest-apply path is a different job ESO's provider model cannot itself express, at any
  configuration.
