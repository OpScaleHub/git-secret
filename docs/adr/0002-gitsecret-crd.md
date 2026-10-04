# ADR-0002 — Kubernetes integration is a native CRD + controller

- Status: **Accepted** (implemented in v0.7; retro-recorded 2026-10)

## Context

Encrypted secrets live in Git; workloads need plaintext `Secret`s. Three
designs were tried or considered before this one:

1. **A GitOps-tool plugin that decrypts during manifest generation.** It
   worked, but plaintext passed through the GitOps tool's generation and caching
   pipeline on every sync, and drift on the live `Secret` was invisible to it.
2. **A third-party secret store behind External Secrets Operator.** A new
   service to run, secure and keep available — for live secret delivery, an
   availability dependency worse than the problem it solves.
3. **An ESO webhook bridge (`git-secret-server`).** Built and run in
   production. It cloned the repository per request, needed an SSH transport
   and host-key trust decision per clone, and made delivery a five-layer chain
   with its own ordering and retry failures.

## Decision

Ciphertext lives **inline in a `GitSecret` custom resource**, delivered by
whatever already applies manifests (any GitOps tool, `kubectl apply`), and a
controller holding its own GPG key reconciles it into a `Secret`. The decrypt
path has no network call, no repository access and no SSH.

## Consequences

- The whole clone/transport/host-key class of problems is gone, structurally.
- Delivery is the normal manifest path — no Keyfold-specific integration with
  any GitOps tool.
- The controller is built on `controller-runtime` (informers, leader election).
- `git-secret-server` was deprecated, then removed after v0.10.0.
