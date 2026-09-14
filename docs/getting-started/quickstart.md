# Quickstart: GitSecret + Kubernetes

End-to-end walkthrough: generate a controller identity, seal a secret,
install the CRD + controller, and watch it reconcile into a plain
`Secret`. Every step below was run and verified against a local
[`kind`](https://kind.sigs.k8s.io/) cluster (Kubernetes v1.34) as part of
writing this doc — commands, output shapes, and the sync condition are
copy-pasted from that run.

This covers the `GitSecret` CRD + controller path (inline ciphertext, no Git
repo access needed at reconcile time). If you want file-level encryption in
a Git repo instead (the original `git secret` CLI), see the [main
README](../../README.md#quick-start).

## Prerequisites

- `go` 1.25+ (to build the binaries; no release binary download is required
  for this walkthrough)
- `gpg`
- A cluster and `kubectl` context — this doc uses `kind`, but any
  Kubernetes v1.28+ cluster works the same way

```bash
kind create cluster   # skip if you already have a cluster/context
kubectl cluster-info
```

## 1. Build the binaries

```bash
git clone https://github.com/OpScaleHub/git-secret.git
cd git-secret
go build -o git-secret-seal ./cmd/git-secret-seal
go build -o git-secret-controller ./cmd/git-secret-controller
```

## 2. Generate the controller's GPG identity

The controller needs its own dedicated key — never reuse a human's key for
this.

```bash
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-generate-key \
  "git-secret-controller <controller@example.com>" default default never

FPR=$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
echo "$FPR"   # you'll use this fingerprint below
```

## 3. Seal a secret

```bash
./git-secret-seal --namespace demo --name my-secrets \
  --recipient "$FPR" --from-literal API_KEY=abc123 > gitsecret.yaml
```

`gitsecret.yaml` now holds a `GitSecret` object with `spec.encryptedData`
(the per-value ciphertext) and `spec.encryptedKey` (the content key, GPG-
wrapped to `$FPR`) — safe to commit to Git or hand to anyone; only a holder
of the matching private key can decrypt it.

## 4. Install the CRD and start the controller

```bash
kubectl create namespace demo
kubectl apply -f config/crd/bases/git-secret.opscalehub.io_gitsecrets.yaml

gpg --export-secret-keys --armor "$FPR" > private.asc
./git-secret-controller --gpg-private-key-file private.asc \
  --watch-namespaces demo &
```

(This runs the controller as a local process talking to your current
`kubectl` context — fine for a quickstart. See [the Helm
chart](../../charts/git-secret-controller/README.md) to run it in-cluster
for real use, which is how you'd normally deploy this.)

## 5. Apply the GitSecret and watch it reconcile

```bash
kubectl -n demo apply -f gitsecret.yaml
kubectl -n demo get gitsecret my-secrets -o jsonpath='{.status.conditions[0].message}'
# => decrypted 1 key(s) into Secret/my-secrets

kubectl -n demo get secret my-secrets -o jsonpath='{.data.API_KEY}' | base64 -d
# => abc123
```

`kubectl get gitsecret my-secrets` also shows a `Recipients` column — who
can decrypt this object — without ever exposing the plaintext itself.

## 6. Clean up

```bash
kill %1   # stop the local controller process
kubectl delete namespace demo
kubectl delete crd gitsecrets.git-secret.opscalehub.io
rm -f private.asc gitsecret.yaml
```

## Next steps

- [Helm chart README](../../charts/git-secret-controller/README.md) — run
  the controller in-cluster instead of as a local process, with RBAC,
  leader election, and the optional admission webhook.
- [Recipient & key lifecycle](../security/recipient-lifecycle.md) — adding,
  removing, and rotating recipients without re-encrypting values.
- [Troubleshooting](../guides/troubleshooting.md) — common failure modes
  and how to diagnose them.
- [Architecture overview](../architecture/overview.md) — the full seal →
  apply → reconcile flow and envelope structure.

If you're looking for the file-level `git secret` CLI (encrypt whole files
in a Git repo, hydrate via hooks) rather than the CRD/controller, start from
the [main README's Quick start](../../README.md#quick-start) instead —
there is no ArgoCD Config Management Plugin integration in this project
today, so a guide for one isn't included here.
