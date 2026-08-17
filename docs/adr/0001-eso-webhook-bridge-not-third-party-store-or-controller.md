---
title: ESO integration via a stateless webhook bridge, not a third-party store or a custom controller
tags: [git-secret, adr, kubernetes, external-secrets-operator, security]
---

# ADR-0001: ESO integration via a stateless webhook bridge, not a third-party store or a custom controller

## Status

Accepted.

## Context

`git-secret` exists to solve one problem: make it safe to commit a secret to a git repository, in
the absence of (or before adopting) a proper external secret-management system. Its whole design
center is *"ciphertext in git, plaintext only locally or at a trusted decrypt point"* — the ArgoCD
Config Management Plugin (CMP) integration already documented in the README is the first worked
example of "trusted decrypt point."

A consuming project — a new, real production PaaS site (internally: `nuc-lab`), standing up its
first paying-customer-facing SaaS — needed a secrets story with a materially higher bar than a home
lab or a demo repo. That search is the direct cause of this ADR, and it's worth recording the full
path, not just the destination, so nobody re-walks it from scratch:

1. **GitHub's own "Secrets" feature was considered as a backend, and ruled out.** Not a scoping or
   permissions problem — GitHub's Actions/repo/org secrets API is write-only *by platform design*.
   No credential of any kind (deploy key, PAT, GitHub App token) can read a secret's value back
   once it's set; the only place the plaintext ever exists again is transiently inside an Actions
   runner. There is no configuration that makes this work.
2. **SaaS-hosted secret stores (1Password, AWS/GCP Secrets Manager) were considered, and set
   aside.** The consuming environment is an Iran-hosted production site with a real, already-lived
   precedent: `registry.k8s.io` got geo-blocked, breaking an image pull. A secret store outside the
   operator's own control risks the exact same failure mode for *live secret reconciliation* —
   which is a meaningfully worse outage than a blocked image pull.
3. **Self-hosted general-purpose stores (Vault, Infisical) were considered next.** Infisical
   specifically turned out to have a genuine first-party ESO provider, needing zero custom code.
   Still set aside: it's a brand-new external dependency to stand up, secure, and operate, when a
   tool already owned and actively maintained (`git-secret` itself) could serve the same purpose
   with less total new infrastructure.
4. **The existing ArgoCD CMP pattern was considered as "good enough as-is," and set aside as the
   long-term answer** — not because it doesn't work (it does, today), but because it routes
   decrypted plaintext through ArgoCD's own manifest-generation/caching pipeline on every sync,
   which is a risk ArgoCD's own documentation calls out directly, and which this project's README
   already flagged before this ADR existed. `selfHeal` also fights any out-of-band fix to a live
   `Secret`, since ArgoCD's diff sees only "did the plugin's output change," not "is the live value
   still correct."
5. **A bespoke Kubernetes controller (its own CRD, its own reconcile loop) in place of wrapping ESO
   was considered, and rejected.** External Secrets Operator already provides the reconcile loop,
   drift detection, deletion policy, status/observability, and RBAC scoping that a hand-rolled
   controller would have to rebuild from scratch, for no functional benefit over reusing it. The one
   genuinely novel piece this project contributes is decryption — not secret lifecycle management —
   so only that piece is worth owning.

What that left, reconstructed as precisely as this record can: **ESO should be the delivery/lifecycle
mechanism; `git-secret`'s own encryption stays the source of truth; no new third-party service gets
introduced.** Repository read access should reuse whatever deploy key the consuming GitOps
controller (ArgoCD, in the worked example) already has — the repository only ever holds ciphertext,
so sharing that specific credential costs nothing. Decryption should use a *new*, dedicated identity
added to the repo the same way a human teammate already is (`git secret adduser`), so the sensitive
half — the decryption key — stays narrowly scoped and independently revocable, never conflated with
the git-transport credential.

## Decision

Add **`git-secret-server`** to this project: a small, stateless HTTP service — explicitly not a
Kubernetes controller — exposing one authenticated endpoint (`GET /decrypt`) that wraps this
project's own, already-tested `DecryptK8sManifest`. It's built specifically to be the backend behind
[External Secrets Operator's generic Webhook `SecretStore` provider](https://external-secrets.io/latest/provider/webhook/).

Concretely:

- **A fresh, isolated `git clone` per request**, not a shared checkout kept current by a background
  poller. Every response reflects the remote's actual current `HEAD`; there's no staleness window
  and no separate sync process to run or monitor. The cost — a clone on every request — is cheap
  against ESO's own reconcile interval (minutes, not sub-second).
- **Repository read access reuses the consuming controller's existing deploy key** rather than
  provisioning a new one — deliberate, not an oversight (see Context above: shared read access to
  ciphertext-only content carries no extra risk).
- **Decryption uses its own dedicated GPG identity**, onboarded via the existing `adduser`
  mechanism. Only the resulting private key ever enters the cluster, as one `Secret`.
- **Bearer-token auth, compared in constant time, fails closed** — a misconfigured empty token
  rejects every request rather than accepting all of them.
- **Bounded concurrency** (`MaxConcurrentClones`, default 4): every request is a real `git clone`,
  so unbounded concurrent requests (a leaked token, a retry storm) could otherwise exhaust the pod.
  A request past the cap gets an immediate `503`, not a queue.
- **Shipped, not just designed**: a container image and a Helm chart, both published on every
  tagged release alongside the existing `git-secret`/`kubectl-secret` binaries. The chart never
  accepts secret material in `values.yaml` — only references to `Secret`s created out-of-band,
  matching this project's own established discipline.

## Consequences

- Any consuming repo that adopts this instead of the CMP pattern gets a real property change:
  ArgoCD's process never has to touch secret plaintext or a decryption key at all. The README's CMP
  section now points here for new setups, while staying documented as-is for repos already on it.
- This is a genuinely new trust boundary for the project: a long-lived, network-reachable process
  holding a live decryption key — a bigger attack surface than the CLI's run-once-and-exit model or
  the CMP sidecar's key-copied-in-for-seconds model. It was built and reviewed with that in mind
  (constant-time auth, pinned SSH host-key verification for known hosts, generic error responses,
  the concurrency cap above), but it's exactly the kind of surface this project's existing
  security-review discipline (25 previously closed findings against the CLI/CMP surface) needs to
  keep being pointed at as this sees real use — this ADR is not a substitute for that.
- Nothing here is coupled to any one consuming project. It ships as a general capability of
  `git-secret` itself, usable by anyone who wants ESO's reconcile/drift-detection ergonomics without
  standing up a separate secret store.
- Explicitly foreclosed, and shouldn't be re-litigated without genuinely new information: GitHub
  Secrets as a backend (structurally impossible), a third-party store as a *required* dependency
  (avoided by design, though nothing stops a future ADR from adding one as an *additional* option),
  and a bespoke Kubernetes controller in place of ESO (strictly more to build and maintain for the
  same result).
