# Sealing console (`git-secret-seal ui`)

A web form for producing `GitSecret` manifests, for people who would rather not
drive the `git-secret-seal` CLI — especially non-Linux users. It is **public-key
only**: it never decrypts, never touches the Kubernetes API, and never persists
anything. The output is a manifest you review and `kubectl apply` yourself.

## Run it locally

```
git-secret-seal ui                 # http://127.0.0.1:8765
git-secret-seal ui --keyring envs/prod/keyring.yaml --namespace prod
```

Same trust boundary as running `git-secret-seal` directly — the sealing happens
in the process, using the recipient **public** keys in your gpg keyring (or the
ones carried in `--keyring`). Nothing leaves your machine.

## Run it in-cluster

Helm (`charts/git-secret-controller`):

```yaml
sealUi:
  enabled: true
  keyringConfigMap: git-secret-keyring   # optional: pre-fills recipients
  defaultNamespace: ""
```

This deploys a small `Deployment` + `Service` running `git-secret-seal ui` from
the controller image (the binary is bundled). The pod has
`automountServiceAccountToken: false` — it genuinely cannot reach the API.

Reach it by port-forward — **no Ingress**:

```
kubectl port-forward svc/git-secret-controller-seal-ui 8080:80
open http://localhost:8080
```

### Residual risk, stated plainly

Sealing runs in the process, so for the in-cluster deployment the plaintext you
type travels browser → `kubectl port-forward` tunnel (apiserver-authenticated
TLS) → the pod, and sits in the pod's memory for the duration of one request. It
is never written anywhere and never sent to the cluster API. If that transit is
not acceptable for a given secret, run the UI locally instead, or use the CLI.

Doing the GPG work in the browser (WASM OpenPGP) would remove even that transit;
it is a possible future hardening, not built.

**In-cluster reachability.** The UI has no auth of its own, so `kubectl
port-forward` is not the only path to it — any pod that can route to the
ClusterIP `Service` can `POST /api/seal`. The blast radius is bounded (public-key
only, nothing decrypted, nothing persisted, the caller cannot apply the manifest
they get back), so this is availability, not confidentiality: the chart caps
concurrent `/api/seal` at `sealUi.maxInflight` (excess → HTTP 429) and each seal
runs under a 30s deadline, and ships a `NetworkPolicy` that locks egress to DNS.
Restrict ingress too with `sealUi.networkPolicy.allowFrom` if you do not want
every pod in the cluster able to reach it.

## The keyring

`keyringConfigMap` names a `ConfigMap` with a `keyring.yaml` key in the
[keyring format](keyring.md), extended with an optional armored `publicKey` per
entry:

```yaml
recipients:
  - fingerprint: 1111...
    role: controller
    publicKey: |
      -----BEGIN PGP PUBLIC KEY BLOCK-----
      ...
  - fingerprint: 2222...
    role: recovery
    publicKey: |
      -----BEGIN PGP PUBLIC KEY BLOCK-----
      ...
```

The UI imports those public keys into an ephemeral keyring at startup, so
in-cluster sealing works without any operator keyring. Build the `publicKey`
blocks with `gpg --armor --export <fpr>` (or, for the controller's own key,
`git-secret-controller --print-public-key`).

## What it does not do

No decryption. No `kubectl apply`. No cluster API access. No storage. No auth of
its own — the port-forward (and, if you add one, your cluster's auth proxy or an
ingress `NetworkPolicy`) is the boundary. It is an authoring convenience, not a
control point: what reaches the cluster is still gated by whoever applies the
manifest.
