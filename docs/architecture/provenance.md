# Secret provenance

Answering "which Git revision produced this `Secret`?" — threat-model T10.

The controller reconciles whatever `GitSecret` object it is given; it has no notion
of "newer", so a force-push or bad revert that delivers an old object version
silently rolls the live `Secret` back. Provenance metadata makes that visible.

## Two revisions, two sources

| What | Set by | Where |
|---|---|---|
| The commit the **plaintext** was sealed from | `git-secret-seal` | `git-secret.opscalehub.io/source-revision` annotation → mirrored to `status.sourceRevision` |
| The commit the **`GitSecret` object** was applied from | your GitOps tool | e.g. `argocd.argoproj.io/tracking-id`, or ArgoCD's app sync revision |

`git-secret-seal` stamps its annotation automatically when run inside a Git
working tree:

```
$ git-secret-seal --namespace prod --name app --recipient <fpr> --from-env-file app.env
# gitsecret.yaml metadata.annotations:
#   git-secret.opscalehub.io/source-revision: 4f2a1c9...        (HEAD, "-dirty" appended if the tree is dirty)
#   git-secret.opscalehub.io/source-repo: git@github.com:org/app.git
```

- `--source-revision <sha>` overrides it (for CI that seals from a detached
  checkout, or a build system that knows the real revision).
- `--no-provenance` omits both annotations.

`--rewrap` and `git-secret-seal recipients` preserve whatever annotations the
object already has — provenance is set once, at seal time.

## Reading it

```
kubectl get gitsecret app -n prod -o jsonpath='{.status.sourceRevision}'
kubectl get gitsecret -n prod -o wide     # Revision column (priority 1)
```

## Not done (bigger design question)

Rollback *protection* — a `spec` field naming a minimum/expected revision the
controller refuses to go below — is deliberately out of scope here. It needs a
trust model for who sets that field and how it is bumped, and is better as its
own proposal. This change is only about making the current revision *observable*.
