# ADR-0007 — The sealing console seals server-side, public keys only

- Status: **Accepted** (since v0.9)

## Context

People who don't use the CLI still need to produce `GitSecret` manifests,
including from inside a cluster with no operator keyring.

## Decision

`keyfold ui` serves a small web form; sealing runs **in that process**, using
public keys only — the operator's keyring locally, or (in-cluster,
`--isolated-keyring`) a keyring ConfigMap whose entries carry their verified
public keys. In-cluster it has no ServiceAccount token, no Ingress (reach it by
`kubectl port-forward`), egress limited to DNS, bounded concurrency.

## Consequences

- It can never decrypt or apply anything; its output is a manifest to review.
- For the in-cluster form, plaintext travels browser → port-forward tunnel → pod
  memory for one request. Sealing in the browser (WASM) would remove that and
  remains a possible future step.
- Whoever can edit the keyring ConfigMap decides who can decrypt what it seals.
