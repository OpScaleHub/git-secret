# Sealing console — feasibility (not scheduled)

Status: **design analysis only.** No console is built or planned. This records the
thinking so a future decision starts from here instead of from scratch (#46).

## What it would be

A web UI for the `git-secret-seal` workflow: pick recipients, enter key/value
pairs (or paste a `Secret` manifest), see the YAML, get a `GitSecret` manifest
out. Nothing else.

## What it is not, ever

- **Not a decrypt endpoint.** Sealing is a one-way, public-key-only operation — it
  needs recipient *public* keys and plaintext input, and produces ciphertext. It
  never holds or needs a private key.
- **Not part of `git-secret-controller`.** A separate binary / Deployment, always.
  Bolting a sealing endpoint onto the always-on process that holds the decrypt
  key is exactly the trust-domain mixing the CRD design exists to avoid.
- **Not an authorization point.** The generated manifest still goes through
  `kubectl apply` / ArgoCD / PR review. The apply path is the control boundary;
  the console is an authoring convenience.

## Deployment shapes

| Shape | Exposure | Notes |
|---|---|---|
| **Local, CLI-launched** (`git-secret-seal ui`, binds `127.0.0.1`, auto-exits) | Lowest — plaintext never leaves the operator's machine | Same trust boundary as running the CLI today |
| **In-cluster Deployment**, reached by `kubectl port-forward` (no Ingress) | Medium — see risks below | A shared, always-available authoring surface |
| **In-cluster sidecar / one-shot Job** | Medium | On-demand variant of the above |

## Residual risks for an in-cluster console, and mitigations

1. **Plaintext in transit / in the pod.** *Mitigation:* do the GPG sealing
   **client-side in the browser** (WASM OpenPGP). The server then serves only
   static assets + the recipient public-key list (from the [keyring](keyring.md)),
   and plaintext never leaves the browser tab. This is the design that makes
   in-cluster ≈ as safe as local, and is the thing to **prototype first** before
   committing.
2. **Recipient substitution** (a compromised console seals to an attacker key
   too). *Mitigation:* `spec.recipients` is visible in the manifest diff and the
   manifest goes through review before it means anything.
3. **Authz** (who may use it, for which namespace). *Mitigation:* not the
   console's job — the apply path already gates this. Optionally put the
   port-forward behind the cluster's normal auth proxy.

## Hard dependency

Recipient public-key discovery — **done** ([keyring.md](keyring.md):
`git-secret-controller --print-public-key`, `git-secret-seal --keyring`). A
console would build its recipient picker on the keyring file.

## Recommendation

**Not worth building now** — there is no demonstrated CLI pain; recent real
production use went end-to-end on `git-secret-seal` without friction, and
`--keyring` removes the "retype every fingerprint" annoyance that would have been
the main driver.

If sealing frequency grows enough that the CLI is a real bottleneck for several
people, the path is:

1. Prototype the **local, browser-side-crypto** shape (`git-secret-seal ui`).
2. Only if a shared surface is genuinely needed, extend the *same* browser-side
   -crypto build to an in-cluster Deployment behind `port-forward`.
3. Never a server-side-seal endpoint; never on the controller.
