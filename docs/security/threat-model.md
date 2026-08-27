# Threat model

Status: **initial draft** (tracking issue #38). Covers the two shipped shapes:

1. **CLI + Git hooks** — `git-secret` encrypting files in a repo, `file` / `env` /
   `gpg` key backends.
2. **`GitSecret` CRD + `git-secret-controller`** — inline ciphertext reconciled
   into a Kubernetes `Secret`.

See [architecture/overview.md](../architecture/overview.md) for diagrams of the
flow, the envelope, and the trust/recovery model.

The legacy ESO webhook bridge (`git-secret-server`) is in maintenance and is not
re-analysed here; its review is issues #1–#25.

This document states what is defended, against whom, and the invariants the code
must preserve. It is reviewed before any new network-facing surface is added.

---

## 1. Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Plaintext secret values | Operator workstation (working tree), controller memory during reconcile, target `Secret` | **Critical** |
| Encrypted repo + full Git history | Git host, every clone | Confidential (durable source of truth) |
| Content-encryption keys (per file / per `GitSecret`) | Only ever in memory, wrapped at rest in `key.gpg` / `spec.encryptedKey` | **Critical** |
| Recipient **private** keys (human) | Operator GPG keyrings, offline backups | **Critical** |
| Recipient **private** key (controller) | One Kubernetes `Secret`, imported into an ephemeral `GNUPGHOME` at startup | **Critical** |
| Recipient **public** keys | Local keyrings today; a discoverable keyring is proposed (#47) | Public |
| `GitSecret` objects | etcd, Git (as manifests), every apply path | Confidential |
| Target `Secret` objects | etcd, mounted into workloads | **Critical** |
| Controller ServiceAccount token / RBAC | Cluster | High |
| Git transport credential (deploy key) | Whatever clones the repo | Medium (guards ciphertext only) |
| Controller logs / Events / `status` / metrics | Cluster, log sinks | Must contain **no** plaintext or key material |
| `.repo-enc.yml` | Git (committed) | Integrity-sensitive (defines encryption policy) |

---

## 2. Trust boundaries

```
 operator workstation ── git push ──▶ Git host ── apply path (ArgoCD/kubectl) ──▶ kube-apiserver
        │                               │                                              │
   local gpg keyring              (ciphertext only)                            git-secret-controller
        │                                                                             │
   git-secret / git-secret-seal                                            ephemeral GNUPGHOME + its key
                                                                                      │
                                                                              target Secret ──▶ workload
```

- **Git host is untrusted for confidentiality**, trusted for availability/integrity
  only to the extent commit history is (see threat T10). It only ever holds
  ciphertext.
- **The apply path (ArgoCD, `kubectl`) is trusted for integrity** — it decides
  which `GitSecret` objects reach the cluster. It never sees plaintext.
- **The controller is trusted with its own key only.** It can decrypt exactly the
  `GitSecret`s whose `encryptedKey` is wrapped to its identity, and nothing else.
- **The operator workstation + local GPG keyring is the root of trust** for the
  CLI workflow. Compromise there is game over for anything that workstation can
  decrypt (T6).
- **etcd / the apiserver is trusted.** A cluster admin who can read `Secret`s
  needs no help from `git-secret` (T8) — this project does not defend against a
  malicious cluster administrator, and does not claim to.

---

## 3. Threats

Notation: **L** = availability/recovery, **C** = confidentiality, **I** = integrity.

| # | Threat | Class | Current posture |
|---|---|---|---|
| T1 | Controller pod / Deployment destroyed | L | **Handled.** State is in Git + the controller `Secret`; a fresh controller reconciles everything back. |
| T2 | Entire cluster lost | L | **Handled.** Re-apply `GitSecret`s to a new cluster + restore the controller key → identical `Secret`s. Runbook §B; test `TestRecovery_ClusterRebuild_SameKeyReproducesData`. |
| T3 | One recipient **private key lost** (holder unavailable) | L | **Handled.** Any other current recipient runs `git-secret-seal --rewrap` to drop it / add a replacement — `encryptedData` is never re-sealed. Runbook §C/§D; tests `TestRecovery_ControllerKeyLost_*`, `TestRecovery_OperatorLeaves_*`. |
| T4 | One recipient **private key compromised** | C | **Partial, and understood.** `--rewrap` stops *future* exposure, but every historical version of the object in Git stays wrapped to the compromised key → permanent historical exposure. Requires rotating the secret values + a new content key + full re-seal. Runbook §E; test `TestRecovery_KeyCompromise_RewrapAloneIsInsufficient`. |
| T5 | Malicious / oversized `GitSecret` applied | I / L (DoS) | **Handled.** `encryptedData` is capped at 1024 entries (CRD `maxProperties` + `sealer.MaxEntries`) and 1 MiB per encoded value; the resulting `Secret` is separately capped by the apiserver. |
| T6 | Operator workstation compromised | C | **Out of scope to prevent.** Blast radius = everything that workstation's keyring can decrypt. Mitigation is operational: per-person keys, hardware-backed keys, offline recovery key not on any workstation. |
| T7 | Plaintext leak via logs / Events / `status` / metrics | C | **Invariant (I3), regression-tested.** `TestUnseal_ErrorDoesNotLeakPlaintext` asserts a tampered-envelope failure never echoes the plaintext into the returned error (which the controller copies into `.status`). |
| T8 | Malicious cluster administrator | C | **Out of scope.** Anyone who can `kubectl get secret -o yaml` wins without touching `git-secret`. |
| T9 | Compromised controller pod | C | Blast radius = `GitSecret`s wrapped to the controller key. Mitigation: don't wrap every object to every controller (per-cluster/per-env recipients, #43); `runAsNonRoot`, read-only rootfs, minimal RBAC. |
| T10 | Rollback / history-rewrite of a `GitSecret` in Git | I | An old object version re-applied re-installs old secret values silently. Provenance (which Git revision produced this Secret) is not surfaced — future work. |
| T11 | Recipient substitution — object sealed to an attacker key alongside the real ones | C | **Partial.** `spec.recipients` now lists the fingerprints on the object, so adding one is a visible one-line diff in review; `sealer.VerifyRecipients` cross-checks the count against the blob and the controller logs a warning on mismatch. Not yet enforced by admission (#41). |
| T12 | Pre-existing target `Secret` silently adopted & cleared | I | **Handled.** A colliding `Secret` this `GitSecret` does not own is left untouched and a `TargetConflict` Ready=False condition is set, unless the operator opts in with `spec.target.adopt`. Tests `TestReconcile_DoesNotClobberUnownedSecret` / `_AdoptsUnownedSecretWhenOptedIn`. |
| T13 | Plaintext committed to Git (CLI path) | C | **Handled.** `verify` + the `pre-push` hook fail closed; `SECRETIZE_SKIP_HOOKS` is opt-in per-invocation, never tied to ambient `CI`. |
| T14 | Recipient specified as a short key ID / email, resolving to the wrong key | C | **Handled.** `gpgutil.ValidFingerprint` requires a full 40/64-hex fingerprint everywhere recipients are accepted. |

---

## 4. Security invariants

Implementations must preserve these. A change that breaks one is a security
regression regardless of the feature it enables.

1. **The controller is never the only holder of a key that can open production
   data.** Every production `GitSecret` is wrapped to at least one offline
   recovery recipient in addition to the controller.
2. **Losing Kubernetes does not lose the secrets.** The encrypted repo + any one
   authorized recipient private key is sufficient for full recovery.
3. **Plaintext never appears in logs, Kubernetes Events, `status`, or metrics** —
   neither secret values nor unwrapped content keys nor private key bytes.
4. **Recipient identity is a full GPG fingerprint**, never a display name, email,
   or short key ID. (`gpgutil.ValidFingerprint`.)
5. **A `GitSecret` decrypts only to the exact object/namespace/key its AEAD was
   bound to.** (`internal/sealer.aad`; `TestUnsealWrongObjectFails`.)
6. **Adding or removing a recipient never re-encrypts `encryptedData`** — only
   `encryptedKey` is rewrapped. (`internal/sealer.Rewrap`.)
7. **The controller decrypts only what its own key can unwrap** — it holds no
   master key and cannot enumerate or open objects sealed to other identities.
8. **`git-secret-seal` never writes plaintext to disk** beyond what the caller
   passed in.
9. **Recipient changes are reviewable** — visible in the Git diff of the object,
   not buried in an opaque re-encrypted blob. *(Depends on #40.)*
10. **The apply path, not any authoring tool, is the authorization boundary** for
    what reaches the cluster.

---

## 5. Non-goals

- Defending against a malicious kube cluster administrator (T8) or a compromised
  operator workstation (T6) — both are outside the model; mitigations for them are
  operational, not cryptographic.
- Preventing historical ciphertext exposure after a key compromise (T4) — Git
  history is immutable by design; the answer is rotation + accepting the exposure
  of anything already committed.
- Being a general-purpose secret store, an identity provider, or a Vault
  replacement.
- Hiding the *existence* or *shape* (key names, recipient count) of a secret —
  only its values are confidential.

---

## 6. Open items feeding this model

#41 (recipient lifecycle / admission) · #43 (multi-cluster blast radius) · #47
(keyring / pubkey discovery).

Closed: #38 (this doc) · #39 (DR runbooks + tests) · #40 (`spec.recipients` +
status mirror + `VerifyRecipients`) · #42 (controller adoption guard, input
bounds, status-leak regression test).
