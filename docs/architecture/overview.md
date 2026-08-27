# Architecture overview

Diagrams for the `GitSecret` CRD + controller path. Companion to
[design-rationale.md](../security/design-rationale.md) (why) and
[threat-model.md](../security/threat-model.md) (what's defended).

## End-to-end: seal → apply → reconcile

```
 ┌─────────────────────┐        ┌──────────────────────────────────────────────┐
 │  operator workstation│        │                Git repository                │
 │                      │        │                (ciphertext only)             │
 │  plaintext value     │        │                                              │
 │        │             │        │   gitsecret.yaml:                            │
 │        ▼             │  git   │     spec.encryptedKey:  <GPG-wrapped CEK>     │
 │  git-secret-seal ────┼──push─▶│     spec.encryptedData: {k: <AEAD envelope>} │
 │   --recipient <ctrl> │        │                                              │
 │   --recipient <you>  │        └───────────────────────┬──────────────────────┘
 │   --recipient <rec>  │                                │ apply path
 │                      │                                │ (ArgoCD / kubectl)
 │  local gpg keyring   │                                ▼
 └─────────────────────┘        ┌──────────────────────────────────────────────┐
                                │                 kube-apiserver               │
                                │              GitSecret object in etcd        │
                                └───────────────────────┬──────────────────────┘
                                                        │ watch
                                                        ▼
                                ┌──────────────────────────────────────────────┐
                                │            git-secret-controller             │
                                │                                              │
                                │  ephemeral GNUPGHOME  ── holds ONLY its own   │
                                │        │                   private key       │
                                │        ▼                                     │
                                │  unwrap encryptedKey ──▶ content key (CEK)    │
                                │        │                                     │
                                │        ▼                                     │
                                │  AEAD-open each encryptedData value           │
                                │  (AAD = "<ns>/<name>/<key>")                  │
                                │        │                                     │
                                │        ▼                                     │
                                │  CreateOrUpdate Secret/<target>  (owned)      │
                                └───────────────────────┬──────────────────────┘
                                                        ▼
                                                 Secret ──▶ workload
```

No repo clone, no SSH, no outbound network call on the decrypt path — the
ciphertext arrives as part of the object via the same apply path as every other
manifest.

## Envelope: two layers

```
  spec.encryptedData["API_KEY"]                spec.encryptedKey
  ┌───────────────────────────┐                ┌───────────────────────────┐
  │ base64(                   │                │ ASCII-armored GPG message │
  │   crypto.Seal envelope:   │   sealed with  │   content key (32 bytes)  │
  │     XChaCha20-Poly1305    │◀──── CEK ──────│   wrapped to N recipients │
  │     AAD = ns/name/key     │                │                           │
  │ )                         │                └───────────────────────────┘
  └───────────────────────────┘                        │
        one per target key                   unwrappable by ANY one of:
                                             ├─ controller's key
                                             ├─ human operator's key
                                             └─ offline recovery key
```

Adding/removing a recipient (`git-secret-seal --rewrap`) re-encrypts **only the
right-hand box**. Every `encryptedData` value is untouched — that is what makes
recipient changes cheap and key loss recoverable.

## Trust model: why loss ≠ compromise

```
        recipient key LOST                    recipient key COMPROMISED
        (holder gone)                         (attacker has it)

  ┌──────────────────────────┐          ┌──────────────────────────────────┐
  │ any other current        │          │ 1. new content key + RE-SEAL     │
  │ recipient runs --rewrap  │          │    every encryptedData value     │
  │ dropping the lost key    │          │ 2. --rewrap to the new key set   │
  │                          │          │ 3. force-update the object       │
  │ encryptedData untouched  │          │ 4. OLD object versions in git    │
  │ → cheap, no re-seal      │          │    history stay wrapped to the   │
  │                          │          │    compromised key → historical  │
  │                          │          │    exposure is PERMANENT for     │
  │                          │          │    anything ever committed       │
  └──────────────────────────┘          └──────────────────────────────────┘
```

Multi-recipient GPG buys redundancy against **loss**. It does not by itself
protect against **compromise** — see threat-model.md T3/T4 and #39.

## Recovery: cluster is disposable

```
   Git repo (encrypted)  ─────────────┬──────────────┬─────────────────┐
          + one authorized            │              │                 │
            recipient private key     ▼              ▼                 ▼
                                 new cluster A   new cluster B    operator laptop
                                 new controller  new controller   git-secret-seal
                                      │               │           --rewrap / decrypt
                                      ▼               ▼
                                 identical Secrets reconciled back
```

The durable artifact is the repo + a key, never the cluster or the controller.
Losing everything Kubernetes-side is a redeploy, not a data-loss event.
