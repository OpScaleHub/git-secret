# Disaster recovery

The reason this project exists: **the encrypted Git repository plus any one
authorized recipient private key is enough to recover every secret.** No
Kubernetes cluster, controller, or single key is a single point of catastrophic
failure.

This document is the operator runbook for each failure mode. Every scenario has a
matching test in [`internal/sealer/recovery_test.go`](../../internal/sealer/recovery_test.go)
— the guarantees are cryptographic, not operational, so they are proven without a
cluster.

See also: [architecture/overview.md](../architecture/overview.md) (the "loss vs
compromise" and "cluster is disposable" diagrams) and
[threat-model.md](threat-model.md) T1–T4.

## Prerequisites for recovery to be possible

These are not optional. Set them up on day one, not after an incident:

1. **Every production `GitSecret` is wrapped to at least one offline recovery
   recipient** — a GPG key held outside any cluster and outside any single
   operator's daily-use keyring (e.g. on a hardware token in a safe). This is
   invariant #1.
2. **The controller's private key is backed up** somewhere independent of the
   cluster it runs in (sealed backup, secret manager, offline media).
3. **The Git repository is mirrored** — the ciphertext is the durable artifact;
   if it only exists on one host, that host is a single point of failure (T-repo).
4. **`git-secret-seal` and `gpg` are available** to whoever holds a recovery key.

## Scenario table

| # | Failure | Recoverable? | Runbook |
|---|---|---|---|
| A | Controller pod / Deployment destroyed | Yes, automatic | [§A](#a--controller-destroyed) |
| B | Entire Kubernetes cluster lost | Yes | [§B](#b--whole-cluster-lost) |
| C | Controller private key lost (no backup) | Yes, if any other recipient survives | [§C](#c--controller-key-lost) |
| D | An operator leaves | Yes | [§D](#d--operator-leaves) |
| E | A recipient private key **compromised** | Partially — see the limit | [§E](#e--recipient-key-compromised) |
| F | `GitSecret` rolled back / rewritten in Git | Yes (re-apply correct revision) | [§F](#f--object-rolled-back-in-git) |
| G | Git repository itself lost | Only from a mirror / backup | [§G](#g--repository-lost) |

---

## A — controller destroyed

**Nothing to do.** The `GitSecret` objects are in etcd (and Git); the target
`Secret`s are owned by them. Redeploy `git-secret-controller` with the same GPG
identity (same `GPG_PRIVATE_KEY_FILE` secret) and it reconciles everything back on
first pass.

If the target `Secret`s were also lost (etcd damage), the controller recreates
them from the `GitSecret`s — no data is only in the `Secret`.

## B — whole cluster lost

1. Stand up a new cluster.
2. Install the CRD (`config/crd/bases/git-secret.opscalehub.io_gitsecrets.yaml`).
3. Restore the controller's GPG identity `Secret` from backup (prereq #2), or —
   if that backup is also gone — generate a new controller identity and follow
   §C to rewrap.
4. Deploy `git-secret-controller`.
5. Re-apply the `GitSecret` manifests (ArgoCD pointed at the same repo does this
   for you).
6. The controller reconciles identical `Secret`s.

Proven by `TestRecovery_ClusterRebuild_SameKeyReproducesData`.

## C — controller key lost

The controller identity is unrecoverable and there is no backup. As long as **any
other recipient** (a human operator, or the offline recovery key) can still
decrypt:

1. Generate a fresh controller identity:
   ```
   gpg --batch --passphrase '' --quick-generate-key 'git-secret-controller <ops@example.com>' default default never
   gpg --armor --export-secret-keys <new-fpr> > controller-key.asc
   ```
2. On a machine holding a surviving recipient's private key, and with the new
   controller's **public** key imported, rewrap every affected object:
   ```
   git-secret-seal --rewrap gitsecret.yaml \
     --recipient <new-controller-fpr> \
     --recipient <human-fpr> \
     --recipient <recovery-fpr>
   ```
   `--rewrap` replaces `spec.encryptedKey` only — no value is re-encrypted.
3. Commit the rewrapped manifests; load `controller-key.asc` into the cluster as
   the controller's `Secret`; deploy.

Proven by `TestRecovery_ControllerKeyLost_HumanRewrapsToNewController`.

## D — operator leaves

Drop their fingerprint from every object they were a recipient of:

```
git-secret-seal recipients remove <departing-fpr> -f gitsecret.yaml
```

(or, to set the whole list explicitly, `git-secret-seal --rewrap gitsecret.yaml
--recipient <controller-fpr> --recipient <remaining-human-fpr> --recipient
<recovery-fpr>`).

Their key can no longer **unwrap the content key** from any version of the
object sealed after this rewrap.

What this does **not** do: `recipients remove` on the CRD path performs a
*rewrap* — it re-encrypts `spec.encryptedKey` to the new recipient set but keeps
the **same content key** and leaves every `spec.encryptedData` value untouched
(invariant #6). A departing operator whose key ever unwrapped that content key
(one `git-secret-seal` unseal, or a copy of a historical `encryptedKey` wrapped
to them) may have kept it, and it still opens every `encryptedData` value that
has not since been **changed**. Only changing a value — which forces a full
re-`Seal` under a fresh content key (§E, step 2) — cryptographically locks them
out. They can likewise still decrypt any version already in Git history that was
wrapped to them.

For a passive reviewer leaving on good terms this is usually fine. If the
departing operator must be denied access to the *current, unchanged* secret
values, treat it as §E (compromise): rotate the values at their source and
re-seal.

> The CLI path differs. `git secret removeuser` (the `gpg` file backend) forces a
> full `rotate-keys` — a fresh content key, every matched file re-encrypted — so
> CLI recipient removal **is** a cryptographic revocation of access to current
> data. The CRD `recipients remove` is a rewrap, not a rotation; do not assume
> the two have the same semantics.

Proven by `TestRecovery_OperatorLeaves_RewrapDropsKeyUnwrap` (the removed key can
no longer unwrap the rewrapped `encryptedKey`); the residual-access limit is
covered by `TestRecovery_KeyCompromise_RewrapAloneIsInsufficient`.

## E — recipient key compromised

**The limit of the design, stated plainly:** multi-recipient GPG protects against
*loss* of a key, not *compromise*. A `--rewrap` stops the compromised key from
opening future object versions, but every prior version of that object lives in
Git history wrapped to the compromised key, and re-wrapping cannot reach into
history. Anything ever committed to that object must be considered exposed.

Response:

1. **Rotate the secret values themselves** at their source (new DB password, new
   API token, …). This is the only step that actually restores confidentiality
   for data already in history.
2. Re-seal under a fresh content key (a normal `git-secret-seal` run, not
   `--rewrap`), dropping the compromised recipient:
   ```
   git-secret-seal --namespace prod --name app-secrets \
     --recipient <controller-fpr> --recipient <human-fpr> --recipient <recovery-fpr> \
     --from-literal DB_PASSWORD=<new-value> ... > gitsecret.yaml
   ```
3. Commit and let it reconcile.
4. Revoke the compromised GPG key (`gpg --gen-revoke`) and distribute the
   revocation.

Proven by `TestRecovery_KeyCompromise_RewrapAloneIsInsufficient`, which asserts
both halves: the compromised key cannot open the rewrapped/re-sealed object, and
it *can* still open the pre-rewrap object (historical exposure is real).

## F — object rolled back in Git

A force-push or bad revert can make the apply path deliver an old `GitSecret`.
The controller will faithfully reconcile whatever it is given — it has no notion
of "newer". Recovery: restore the correct revision in Git and re-apply. Surfacing
which Git revision produced a given `Secret` is future work (threat-model.md T10).

## G — repository lost

The ciphertext is the durable artifact. Recover the repo from a mirror or backup
(prereq #3), then proceed as normal. If no copy of the repo exists anywhere, the
secrets are gone — there is no key that helps, because there is no ciphertext to
apply it to. **This is why prereq #3 is not optional.**

---

## One-liner for the README

> Losing the Kubernetes cluster does not mean losing the secrets, as long as the
> Git repository and one authorized recipient private key survive.
