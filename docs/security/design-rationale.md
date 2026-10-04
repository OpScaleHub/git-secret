# Design rationale & history

Why Keyfold looks the way it does. The decisions themselves are recorded as
[ADRs](../adr/); this page is the short story connecting them.

## The thesis

It should be safe to commit a secret to Git: **the encrypted repository is the
durable source of truth, and decryption is multi-recipient, recoverable, and
Kubernetes-native — no single cluster, controller, or key is a single point of
catastrophic failure.** Everything else serves that sentence.

## How it got here

**A Git plugin first.** The project began as `git-secret` (renamed to Keyfold —
[ADR-0001](../adr/0001-product-name.md)): git hooks that encrypt files on
commit and decrypt them on checkout, with the key optionally GPG-wrapped to
several people. That is still the Git plugin, `git keyfold`.

**Getting secrets into Kubernetes took three tries**
([ADR-0002](../adr/0002-gitsecret-crd.md)):

1. *Decrypt inside a GitOps tool's manifest generation.* Worked, but plaintext
   flowed through the tool's generation and caching on every sync, and drift on
   the live `Secret` went unnoticed.
2. *A third-party secret store behind External Secrets Operator.* Rejected: a
   new service to run and keep available, for something that should not need
   one. (A hosted Git service's own secrets feature can't serve either — its API
   is write-only by design.)
3. *A bridge service (`git-secret-server`) that External Secrets Operator
   called.* Built and run in production. It proved the useful parts — Git can
   stay ciphertext-only, the repository credential and the decryption key are
   different things — and exposed the costs: a network-reachable process holding
   a live decryption key, a repository clone and SSH host-key decision per
   request, and a long delivery chain with its own failure modes. Removed after
   v0.10.0.

**The answer was to stop fetching.** Ciphertext became an inline custom resource
(`GitSecret`) applied like any other manifest, decrypted by a controller with no
network path at all — and built on the multi-recipient envelope
([ADR-0003](../adr/0003-multi-recipient-envelope.md)) so that losing the
controller's key is a routine rewrap, not a disaster.

**Then recovery was made real end to end.** Recipient lists and roles became
visible on the object; recipient changes became bulk operations; `rekey`, `set`
and offline `unseal` closed the gaps between "rewrap", "rotate" and "recover"
([ADR-0004](../adr/0004-rewrap-is-not-revocation.md)). Convenience features —
a sealing console, public-key publishing, an admission webhook — were added
without ever serving plaintext ([ADR-0005](../adr/0005-no-decrypt-endpoint.md),
[0006](../adr/0006-webhook-self-signed-single-replica.md),
[0007](../adr/0007-server-side-sealing-console.md)).

## Deliberately foreclosed

Re-open these only with genuinely new information:

- **A third-party secret store as a required dependency.** An optional backend
  could be added behind the same interface; a required one would recreate the
  availability problem above.
- **A decrypt endpoint anywhere in the cluster** ([ADR-0005](../adr/0005-no-decrypt-endpoint.md)).
- **Rewrap as revocation** ([ADR-0004](../adr/0004-rewrap-is-not-revocation.md)).

## What Keyfold is not

Not Vault, not a hosted secret manager, not a password manager, not a
replacement for GPG, not an identity provider, and not tied to any one GitOps
tool or Git host. Still useful with no Kubernetes at all — the Git plugin with
the `gpg` backend is the whole product for a team that just wants secrets in Git.
