# Architecture decision records

Short records of decisions that are settled. Each says what was decided, why,
and what it costs. Re-open one only with genuinely new information — and then
with a new ADR that supersedes it, not an edit.

| # | Decision | Status |
|---|---|---|
| [0001](0001-product-name.md) | Rename the product to Keyfold | Accepted |
| [0002](0002-gitsecret-crd.md) | Kubernetes integration is a native CRD + controller | Accepted |
| [0003](0003-multi-recipient-envelope.md) | Per-object content key, wrapped to many independent recipients | Accepted |
| [0004](0004-rewrap-is-not-revocation.md) | Rewrap, rekey and secret rotation are distinct operations | Accepted |
| [0005](0005-no-decrypt-endpoint.md) | Nothing in the cluster serves plaintext on request | Accepted |
| [0006](0006-webhook-self-signed-single-replica.md) | Admission webhook: self-signed, single replica, never decrypts | Accepted |
| [0007](0007-server-side-sealing-console.md) | The sealing console seals server-side, public keys only | Accepted |

The longer narrative of how the design got here is in
[design-rationale.md](../security/design-rationale.md).
