# ADR-0005 — Nothing in the cluster serves plaintext on request

- Status: **Accepted**

## Context

A network-reachable process that returns decrypted values (the old ESO bridge)
is a standing attack surface. Convenience features — a UI, an API — tend to
grow one.

## Decision

- The controller decrypts **only** into the target `Secret` of an object wrapped
  to its own key; it exposes no decrypt API.
- The sealing console and `GET /pubkey` handle **public keys only**.
- Reading values back is `keyfold unseal`: an offline CLI using the operator's
  own recipient key, printing to stdout only.

## Consequences

- Who can read plaintext in the cluster is exactly who can read the `Secret`
  (Kubernetes RBAC); Keyfold adds no other path.
- Recovery never depends on the cluster being up.
