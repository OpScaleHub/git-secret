# Quickstart: Keyfold on Kubernetes

Install the controller, seal a secret to **the cluster, an offline recovery key
and yourself**, watch it become a `Secret` — then read it back with no cluster
at all. About ten minutes on any Kubernetes ≥ 1.28 (a local
[`kind`](https://kind.sigs.k8s.io/) cluster is fine). New to the model? Read
[concepts](../concepts.md) first; it's one page.

You need `kubectl`, `helm`, `gpg`, `jq`, and the `keyfold` CLI
(`keyfold-<os>-<arch>` from the
[releases](https://github.com/OpScaleHub/git-secret/releases) — rename it to
`keyfold` and put it on `PATH` — or `go build -o keyfold ./cmd/keyfold`).

## 1. Three identities

A secret should never depend on one key. Make a dedicated **controller**
identity for this cluster and an offline **recovery** identity; you are the
third recipient. Each lives in its own `GNUPGHOME` here only to keep the
walkthrough self-contained — in real life the recovery key belongs on a
hardware token or an offline machine, never on the cluster or a laptop.

```bash
export KF=$(mktemp -d) && cd "$KF"
for id in controller recovery; do
  mkdir -m 700 "$id"
  GNUPGHOME="$PWD/$id" gpg --batch --passphrase '' \
    --quick-generate-key "keyfold-$id <$id@example.invalid>" default default never
done
fpr() { GNUPGHOME="$1" gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}'; }
CTRL=$(fpr "$PWD/controller") RECOVERY=$(fpr "$PWD/recovery")
ME=$(fpr "${GNUPGHOME:-$HOME/.gnupg}")      # your own key
```

## 2. Install the controller

Only the controller's **private** key goes into the cluster.

```bash
kubectl create namespace keyfold-system
GNUPGHOME="$PWD/controller" gpg --export-secret-keys --armor "$CTRL" > controller.asc
kubectl -n keyfold-system create secret generic keyfold-gpg --from-file=private.asc=controller.asc
rm controller.asc

helm install keyfold oci://ghcr.io/opscalehub/charts/keyfold \
  --namespace keyfold-system --set gpgPrivateKey.existingSecret=keyfold-gpg --wait
```

The chart installs the `GitSecret` CRD and runs under Pod Security
`restricted`. See the [chart README](../../charts/keyfold/README.md) for the
admission webhook, public-key publishing, metrics and RBAC scoping.

## 3. A keyring for this environment

Commit one of these per environment, so "who can decrypt prod" is a reviewed
file rather than tribal knowledge. Embedding the public keys lets anyone seal
or rewrap without importing them first.

```bash
pub() { GNUPGHOME="$1" gpg --armor --export "$2" | sed 's/^/      /'; }
cat > keyring.yaml <<EOF
recipients:
  - fingerprint: $CTRL
    role: controller
    publicKey: |
$(pub "$PWD/controller" "$CTRL")
  - fingerprint: $RECOVERY
    role: recovery
    publicKey: |
$(pub "$PWD/recovery" "$RECOVERY")
  - fingerprint: $ME
    role: human
    publicKey: |
$(pub "${GNUPGHOME:-$HOME/.gnupg}" "$ME")
EOF
```

## 4. Seal and apply

```bash
kubectl create namespace demo
keyfold seal --namespace demo --name db --keyring keyring.yaml \
  --from-literal DB_USER=app --from-literal DB_PASSWORD=hunter2 > db.yaml

keyfold recipients list -f db.yaml       # controller, recovery, human
kubectl apply -f db.yaml                 # or commit it and let your GitOps tool apply it
kubectl -n demo get gitsecret db         # READY True, RECIPIENTS 3
kubectl -n demo get secret db -o jsonpath='{.data.DB_PASSWORD}' | base64 -d
```

`db.yaml` is safe to commit: it holds only ciphertext, the recipient list, and
which commit it was sealed from. (A literal on the command line lands in shell
history — for real secrets use `--from-env-file` or `-f secret.yaml`.)

## 5. Recover without the cluster

The point of three recipients: with the recovery key alone — no cluster, no
controller, no network — the values come back.

```bash
GNUPGHOME="$PWD/recovery" keyfold unseal -f db.yaml | jq .
```

## 6. Clean up

```bash
kubectl delete namespace demo
helm -n keyfold-system uninstall keyfold && kubectl delete namespace keyfold-system
kubectl delete crd gitsecrets.keyfold.opscalehub.io
cd / && rm -rf "$KF"
```

## Next

- [Concepts](../concepts.md) — rewrap vs rekey vs secret rotation, who can do what.
- [Multi-cluster](../architecture/multi-cluster.md) — add a second cluster to
  every object in one command, without re-encrypting a value.
- [Recipient lifecycle](../security/recipient-lifecycle.md) and
  [disaster recovery](../security/disaster-recovery.md) — runbooks.
- [`keyfold` reference](../reference/keyfold.md) and
  [troubleshooting](../guides/troubleshooting.md).
