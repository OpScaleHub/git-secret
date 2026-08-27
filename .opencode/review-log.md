# Review Log

## 2026-08-17 — PR #28 — Add git-secret-server: ESO webhook bridge
- by: opencode, model big-pickle, on behalf of AliRezaTaleghani
- verdict: commented (no blockers, ready to merge)
- key findings: Security model verified (constant-time auth, concurrency cap, temp cleanup, isolated GNUPGHOME, non-root Docker, NetworkPolicy default-deny). Tests comprehensive across auth, path traversal, concurrency, freshness, and graceful shutdown. Helm chart follows best practices.
- CI: Build/vet/test (macOS, Ubuntu, Windows) + Helm lint/render all passed
- issues: n/a

## 2026-08-17 — PR #29 — Tighten default NetworkPolicy to same-namespace + document recommended namespace
- by: opencode, model big-pickle, on behalf of AliRezaTaleghani
- verdict: commented (no blockers, ready to merge)
- key findings: Follow-up to PR #28 nit. Removed namespaceSelector: {} from default NetworkPolicy.allowFrom, leaving bare podSelector (same-namespace scope). Added chart README section documenting co-location recommendation and cross-namespace override using kubernetes.io/metadata.name labels.
- CI: Build/vet/test (macOS, Ubuntu, Windows) + Helm lint/render all passed
- issues: n/a

## 2026-08-17 — PR #36 — feat: native GitSecret CRD + controller (kubeseal equivalent)
- by: opencode, model big-pickle, on behalf of AliRezaTaleghani
- verdict: commented (2 items before merge)
- key findings: Sound design — inline ciphertext CRD with multi-recipient GPG wrapping, Rewrap for cheap rotation, AAD binding per namespace/name/key. Clean layering: sealer (pure crypto), controller (thin K8s wrapper), CLI (flag-parsing glue). Tests prove actual cryptographic properties (round-trip, AAD enforcement, rewrap-without-re-encryption, wrong-key failure). ADR-0002 makes a persuasive case for why this is categorically different from ESO's webhook bridge.
- CI: macOS and Windows failing (gpg-agent cannot start on GitHub Actions runners). Ubuntu and Helm lint passing.
- issues:
  1. **Blocker:** All GPG-dependent tests fail on macOS/Windows — gpg-agent unavailable. Need t.Skip guard.
  2. **Bug:** CRD printcolumn "Target" uses same JSONPath as "Ready". Should be `.spec.target.name`.
  3. Minor: os.Setenv("GNUPGHOME") not unset in controller entrypoint.
  4. Minor: Significant dependency footprint jump (controller-runtime, k8s.io/*).
