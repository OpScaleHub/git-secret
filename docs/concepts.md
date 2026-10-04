# Concepts

How Keyfold works, in one page: what is encrypted with what, who can do
what, and exactly what each operation changes. Every other document assumes
the terms defined here — the [glossary](#glossary) is at the end.

## The model

Every secret value is encrypted with a **content key**. The content key is then
**wrapped** — encrypted separately — to each **recipient**: a GPG identity such
as a cluster's controller, an operator, or an offline recovery key. Any **one**
recipient's private key can unwrap the content key and read the values. No
recipient depends on any other.

```
   plaintext values                      recipients (GPG public keys)
   ┌────────────────┐                    ┌──────────────────────────┐
   │ DB_PASSWORD=…  │                    │ cluster A controller      │
   │ API_TOKEN=…    │                    │ cluster B controller      │
   └───────┬────────┘                    │ operator (alice)          │
           │ AEAD, one per value         │ offline recovery key      │
           ▼                             └────────────┬─────────────┘
   ┌────────────────┐   content key      ┌────────────▼─────────────┐
   │ encryptedData  │◀── (32 random ─────│ encryptedKey              │
   │  (ciphertext)  │     bytes)         │  content key, wrapped to  │
   └────────────────┘                    │  every recipient above    │
                                         └──────────────────────────┘
        ── both halves are committed to Git; neither is secret ──
```

That split is the whole design:

- **Changing who can decrypt** touches only `encryptedKey` (the right-hand
  box). The values are not re-encrypted — so adding a cluster is a one-line,
  reviewable change, and no recipient has to be online.
- **Recovery needs nothing but the repository and any one recipient key.** Lose
  a cluster, a controller, or a person's key: the remaining recipients can still
  read everything, and can rewrap it to a replacement.
- **Each value is bound to where it was sealed.** Its authenticated data names
  the object (namespace, name, key), so ciphertext copied into another object
  fails to decrypt instead of quietly applying there.

## Two places Keyfold encrypts

The same envelope is used in two independent places. They have **separate
content keys and separate recipient lists**; a team using both maintains both.

| | Kubernetes: `GitSecret` objects | Repository files: the Git plugin |
|---|---|---|
| Tool | `keyfold` + `keyfold-controller` | `git keyfold` (+ `kubectl keyfold` for per-value Secret manifests) |
| What is encrypted | values in a `GitSecret` manifest | whole files matched by `.keyfold.yml` patterns (or single `stringData` values) |
| Content key | **one per object**, in `spec.encryptedKey` | **one per repository**, in `.keyfold/key.gpg` (`gpg` backend) |
| Recipients | `spec.recipients`, usually from a [keyring file](architecture/keyring.md) | `gpg_recipients` in `.keyfold.yml` |
| Who decrypts | the in-cluster controller; anyone with `keyfold unseal` | developers' git hooks (`git keyfold unlock`) |
| Bound to | namespace / name / key | repository + file path (per-value: file, key and object) |

The rest of this page is about `GitSecret`s — the Kubernetes path — unless it
says otherwise.

## Who can do what

| You hold… | You can | You cannot |
|---|---|---|
| **A recipient's private key** (operator, recovery key) | read values (`keyfold unseal`); change recipients (`recipients add/remove`, `--rewrap`); re-key (`rekey`); change values (`set`) | — |
| **Only public keys** | seal *new* objects to them (`keyfold seal`, the sealing UI) | read or modify an existing object |
| **A controller's private key** (in-cluster) | decrypt the objects wrapped to it into `Secret`s | decrypt objects not wrapped to it, or change any object |
| **A new cluster's public key** | be added as a recipient — by someone above | add itself: adding a recipient means unwrapping the current content key, which needs an existing recipient's *private* key |

Rewrapping, rekeying and `set` also need the **public key of every recipient**
the result is wrapped to — in your keyring, or as `publicKey` entries in
`--keyring`.

## What each operation changes

| Operation | Command | `encryptedKey` | `encryptedData` | Values | Use it to |
|---|---|---|---|---|---|
| **Seal** | `keyfold seal` | new | new | as given | create an object |
| **Rewrap** | `keyfold recipients add/remove`, `--rewrap` | content key rewrapped to the new list | **unchanged** | unchanged | add or remove a cluster, person, or recovery key |
| **Rekey** | `keyfold rekey` | **new content key** | all re-encrypted | unchanged | retire a content key someone may have kept (after a removal) |
| **Set** | `keyfold set KEY` | new content key | all re-encrypted | one changed | change or add one value without re-entering the rest |
| **Secret rotation** | change it at its source, then `keyfold set` | new | new | **new** | stop a leaked or departing person's access to the value itself |
| **Unseal** | `keyfold unseal` | — | — | read, to stdout | recover without a cluster |
| **Reconcile** | the controller | — | — | written into a `Secret` | run workloads |
| **Migrate** | `keyfold migrate` | unchanged | unchanged | unchanged | move manifests to a new API group |

On the repository side, `git keyfold adduser` is a rewrap of the repository's
content key; `git keyfold removeuser` and `rotate-keys` are a rekey (every
matched file re-encrypted).

### Removing someone is not revoking what they saw

Git keeps every version of every object. Removing a recipient stops them
unwrapping **future** versions; it cannot reach versions already committed
while they were a recipient, and it cannot make them forget values they read.
So, for someone leaving:

1. `recipients remove` — they can no longer unwrap the current object.
2. `rekey` — a content key they may have kept no longer opens it either.
3. **Rotate the secret at its source** (new database password, new token) and
   `keyfold set` it — the only step that protects the value itself.

How far to go depends on trust: steps 1–2 for a reviewer leaving on good
terms; all three for a compromised key. See
[recipient-lifecycle.md](security/recipient-lifecycle.md) and
[disaster-recovery.md](security/disaster-recovery.md) §D–§E.

## Loss versus compromise

| | A key is **lost** | A key is **compromised** |
|---|---|---|
| Risk | you can no longer decrypt with it | someone else can |
| Fix | any other recipient rewraps to a replacement | rotate every secret it could open, then `set` and remove it |
| Cost | cheap: no value re-encrypted | as large as what that key could read, across Git history |

Multi-recipient wrapping makes **loss** a non-event. It does not, and cannot,
undo **compromise** — that is what secret rotation is for. The full analysis is
in the [threat model](security/threat-model.md).

## Glossary

**AEAD envelope** — the per-value ciphertext format (`RENC` header,
XChaCha20-Poly1305 by default). Authenticated: tampering, a wrong key, or the
wrong binding all fail to decrypt rather than produce garbage.

**Binding (authenticated data)** — what a ciphertext is tied to: for a
`GitSecret` value, its namespace, object name and key; for a repository file,
its path (and repository id). Ciphertext moved elsewhere does not decrypt.

**Content key** (sometimes *CEK*) — the random 32-byte key that encrypts the
values. One per `GitSecret`; one per repository for the Git plugin. Never
stored in plaintext.

**Controller identity** — the GPG key a `keyfold-controller` decrypts with.
One per cluster, never a person's key, never shared between clusters.

**`GitSecret`** — the custom resource (`keyfold.opscalehub.io/v1alpha1`) holding
`encryptedData`, `encryptedKey` and `recipients`, reconciled into a plain
`Secret`.

**Keyring file** — a committed list of recipients (fingerprint, role, optionally
armored `publicKey`) for an environment, used with `--keyring`. Whoever can edit
it decides who can decrypt what is sealed with it.

**Provenance** — the `source-revision` / `source-repo` annotations recording
which commit an object was sealed from; shown as the `Revision` column.

**Recipient** — a GPG identity the content key is wrapped to, named by its full
fingerprint (never a short ID or e-mail). Has a **role**: `controller`,
`recovery`, `human`, or `deprecated`.

**Recovery key** — an offline recipient held outside any cluster and outside
daily use. Every production object should have one; `keyfold` refuses to remove
the last one without `--force`.

**Rekey** — replace the content key: every value re-encrypted, values unchanged.

**Revocation** — there is no undoing a read. "Revoking" a recipient means
rewrap + rekey (no future access) and, if the values themselves must be
protected, secret rotation.

**Rewrap** — re-encrypt the content key to a different recipient list. Values
untouched.

**Seal / unseal** — encrypt values into a manifest / decrypt them back out.

**Secret rotation** — change the secret's actual value where it is used (the
database, the API provider), then record the new value with `keyfold set`.

**Wrap / unwrap** — encrypt / decrypt the content key to / with a recipient's
GPG key.
