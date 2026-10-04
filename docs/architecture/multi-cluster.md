# Multi-cluster operation

Because a `GitSecret` carries its ciphertext inline and the content key is
GPG-wrapped to N independent recipients, "another cluster consuming the same
secret" is just "add that cluster's controller fingerprint as a recipient." No
shared secret store, no central authority, no repo access from the cluster.

This is a design note, not new code — the primitives (`sealer.Rewrap`, recipient
roles, `keyfold recipients`) already exist. It prescribes how to use them.

## Recommended topology

```
                        Encrypted Git repo
                       /       |         \
                      /        |          \
             Cluster A    Cluster B     Recovery
             controller   controller    (offline human key,
             fingerprint  fingerprint    never a controller)
                 |            |
              Secret       Secret
```

- **Each cluster's controller has its own GPG identity.** Never share one keypair
  across clusters — then revoking or rebuilding one cluster is a
  `keyfold recipients remove` that does not touch the others.
- **Do not wrap every object to every cluster.** A prod-only secret is wrapped to
  the prod cluster's controller (+ recovery), not to staging/dev. This keeps the
  blast radius of a compromised cluster controller to exactly the objects that
  cluster was meant to consume.
- **The recovery recipient is cluster-independent** — offline, in every
  production object, so no combination of cluster losses is unrecoverable.

## Environment boundaries

Represent prod / staging / dev as distinct recipient sets, applied at seal time:

```
keyfold recipients list -f gitsecret.yaml
# prod:  <prod-controller>:controller  <recovery>:recovery  <oncall-human>:human
# stage: <stage-controller>:controller <recovery>:recovery
```

Keep one [keyring file](keyring.md) per environment
(`envs/prod/keyring.yaml`, ...) and seal with `keyfold --keyring
envs/prod/keyring.yaml` so the recipient boundary is a reviewable file, not
tribal knowledge. Admission enforcement that objects under `envs/prod/**` match
the prod keyring is not implemented; the webhook enforces required recipients per Namespace instead ([admission-webhook.md](admission-webhook.md)).

## Runbooks

### Add a cluster

**Who can do this:** only an existing recipient of each object — an operator,
or whoever holds the offline recovery key. The new cluster's public key alone
can never add itself: adding a recipient means unwrapping the current content
key, which needs a current recipient's *private* key.

1. Generate the new controller's identity and publish its public key
   (`keyfold-controller --print-public-key`, or the chart's
   `publishPublicKey`); add it, with its armored `publicKey`, to the
   environment's [keyring file](keyring.md).
2. As an existing recipient, add it to every object that cluster should
   consume, in one step:

   ```
   keyfold recipients add <new-controller-fpr> --role controller \
     -f deploy/prod/ --keyring envs/prod/keyring.yaml --dry-run   # preview
   keyfold recipients add <new-controller-fpr> --role controller \
     -f deploy/prod/ --keyring envs/prod/keyring.yaml --write
   ```

   `--keyring` supplies every recipient's public key for this run (each checked
   against its fingerprint, never imported into your keyring). Every file is
   computed first; if any one fails, nothing is written. No value is
   re-encrypted.
3. Commit; point the new cluster's GitOps tool (Argo CD, Flux, …) at the repo;
   deploy its controller.

### Replace / decommission a cluster

1. `keyfold recipients remove <old-controller-fpr> -f deploy/prod/ --write`
   (add `--keyring` if your keyring lacks the remaining recipients' public
   keys), then `keyfold rekey` the objects if the old cluster may have kept
   content keys.
2. Commit. The old controller can still decrypt versions already in Git history
   (see [recipient-lifecycle.md](../security/recipient-lifecycle.md)) — if the
   old cluster is considered compromised rather than merely retired, treat it as
   the compromise case (rotate the secret values).

### Compromised cluster controller

Blast radius = exactly the objects wrapped to that controller's fingerprint.
Rotate those secret values at source, re-seal, and remove the compromised
fingerprint. Other clusters' objects are unaffected because they were never
wrapped to that key.

## Open questions (not blocking)

- Admission enforcement of per-environment recipient sets against the keyring.
- Whether the controller should label recipient fingerprints by cluster in
  `status` (it lists them already; labelling needs the keyring).
