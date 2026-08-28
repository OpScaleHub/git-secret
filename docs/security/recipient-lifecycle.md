# Recipient & key lifecycle

Multi-recipient GPG is the project's core differentiator, but "a flat list of
fingerprints" is not a lifecycle. This document defines the roles a recipient can
have, the workflows for changing the set, and — importantly — what those changes
do and do **not** protect against.

Companion to [disaster-recovery.md](disaster-recovery.md) (the incident runbooks)
and [threat-model.md](threat-model.md) T3/T4/T11.

## Recipient roles

Roles are a **convention**, recorded in the
`git-secret.opscalehub.io/recipient-roles` annotation on the `GitSecret`
(`<fingerprint>:<role>`, comma-separated). The controller never reads them — the
decrypt path only cares what `encryptedKey` is actually wrapped to. They exist so
an operator can tell at a glance which key is which.

| Role | What it is | Notes |
|---|---|---|
| `human` | An operator who seals / reviews locally | The default when a fingerprint has no entry |
| `controller` | A `git-secret-controller` identity | One per cluster (see [multi-cluster](../architecture/overview.md)) |
| `recovery` | An offline key, held outside any cluster and outside any daily-use keyring | **Every production `GitSecret` should have one.** `git-secret-seal` refuses to remove the last one without `--force` |
| `deprecated` | A recipient being phased out — still wrapped to, flagged for a later rewrap to drop | |

## "Who can decrypt this object?"

```
git-secret-seal recipients list -f gitsecret.yaml
```

prints each fingerprint and its role. The set also appears as `spec.recipients`
in the manifest and `status.recipients` on the live object
(`kubectl get gitsecret` shows a `Recipients` count column).

## Workflows

| Change | Command | Re-seal values? | Historical exposure? |
|---|---|---|---|
| Add a recipient | `git-secret-seal recipients add <fpr> -f f.yaml [--role R]` | No | — |
| Remove a recipient (clean) | `git-secret-seal recipients remove <fpr> -f f.yaml` | No | They keep access to versions already in Git history |
| Rotate the controller identity | `recipients add <new>` then `recipients remove <old>` | No | — |
| Rotate a **compromised** key | full `git-secret-seal` re-seal + rotate the secret values themselves | **Yes** | Permanent for anything ever committed — see below |
| Emergency: rotate everything | re-seal every `GitSecret` to a fresh recipient set | Yes | As above |

`add` / `remove` rewrap the content key to the new set and print the updated
manifest; commit it and the controller reconciles. Both need a local GPG secret
key that can already open the object (run them as a current recipient); `add`
also needs the new fingerprint's public key in your keyring (`gpg --import`, WKD,
or a keyserver — see [keyring.md](../architecture/keyring.md)).

## Key expiry

A GPG recipient key can expire. The controller does **not** fail an existing
object on recipient-key expiry (the data is already there and still decryptable
by the controller's own key), but surfacing an early warning
(`RecipientKeyExpiring` condition / metric) is planned. Until then: track expiry
out of band and `recipients add` a renewed key before the old one lapses.

## Historical ciphertext — the property to understand

Because a `GitSecret` is delivered through Git, **every prior version of the
object stays in Git history**, each wrapped to whatever recipient set it had at
the time. Consequences:

- **Removing a recipient** stops them decrypting *new* object versions. It does
  **nothing** about versions already in history that were wrapped to them, which
  they can still open if they have a copy of the repo. For a departing operator
  who was only ever a passive reviewer this is usually fine; treat it as a
  compromise (below) if it isn't.
- **A compromised key** must be assumed to have decrypted everything that key was
  ever a recipient of, across all of history. `--rewrap` / `recipients remove`
  cannot reach into history. The only real remediation is to **rotate the secret
  values at their source** (new DB password, new token) and re-seal — see
  [disaster-recovery.md §E](disaster-recovery.md#e--recipient-key-compromised).

This is not a flaw to fix — Git history is immutable by design — it is a property
to design around: keep genuinely long-lived, un-rotatable secrets out of Git, and
give every production object a `recovery` recipient so a compromise never forces
an unrecoverable state.
