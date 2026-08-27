# Multi-cluster operation

Because a `GitSecret` carries its ciphertext inline and the content key is
GPG-wrapped to N independent recipients, "another cluster consuming the same
secret" is just "add that cluster's controller fingerprint as a recipient." No
shared secret store, no central authority, no repo access from the cluster.

This is a design note, not new code — the primitives (`sealer.Rewrap`, recipient
roles, `git-secret-seal recipients`) already exist. It prescribes how to use them.

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
  `git-secret-seal recipients remove` that does not touch the others.
- **Do not wrap every object to every cluster.** A prod-only secret is wrapped to
  the prod cluster's controller (+ recovery), not to staging/dev. This keeps the
  blast radius of a compromised cluster controller to exactly the objects that
  cluster was meant to consume.
- **The recovery recipient is cluster-independent** — offline, in every
  production object, so no combination of cluster losses is unrecoverable.

## Environment boundaries

Represent prod / staging / dev as distinct recipient sets, applied at seal time:

```
git-secret-seal recipients list -f gitsecret.yaml
# prod:  <prod-controller>:controller  <recovery>:recovery  <oncall-human>:human
# stage: <stage-controller>:controller <recovery>:recovery
```

A future `git-secret-seal` policy/profile file could enforce "objects under
`envs/prod/**` must be sealed to exactly this set" — tracked with #47 (keyring).

## Runbooks

### Add a cluster

1. Generate the new controller's identity; import its public key locally.
2. `git-secret-seal recipients add <new-controller-fpr> -f obj.yaml --role controller`
   for every object that cluster should consume.
3. Commit; point the new cluster's ArgoCD at the repo; deploy its controller.

### Replace / decommission a cluster

1. `git-secret-seal recipients remove <old-controller-fpr> -f obj.yaml` for every
   object.
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

- A `git-secret-seal` policy file for enforcing per-environment recipient sets.
- Whether the controller should expose, in `status`, which *other* clusters'
  fingerprints an object is wrapped to (it can already list the fingerprints; it
  cannot label them by cluster without the keyring in #47).
