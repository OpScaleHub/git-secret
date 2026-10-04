# Example: Keyfold on Kubernetes

[`demo.sh`](demo.sh) is the [Kubernetes quickstart](../../docs/getting-started/quickstart.md)
as one script, run against your current `kubectl` context:

1. three GPG identities — the cluster's controller, an offline recovery key, an operator;
2. the chart installed into a Pod Security `restricted` namespace;
3. a keyring file with the three public keys embedded;
4. a `GitSecret` sealed to all three, applied, and reconciled into a `Secret`;
5. the value read back with the **recovery key alone** — no cluster involved.

```bash
./examples/kubernetes/demo.sh                     # released chart from GHCR
DEMO_CLEANUP=1 ./examples/kubernetes/demo.sh      # …and remove it all afterwards

# from a checkout, with a locally built image in a kind cluster:
docker build -t keyfold-controller:dev -f Dockerfile . && kind load docker-image keyfold-controller:dev
CHART=./charts/keyfold CHART_ARGS="--set image.repository=keyfold-controller --set image.tag=dev --set image.pullPolicy=Never" \
  KEYFOLD=$(go env GOPATH)/bin/keyfold ./examples/kubernetes/demo.sh
```

It needs `kubectl`, `helm`, `gpg` and the `keyfold` CLI. Identities are generated
in a temporary directory; in real use the recovery key belongs offline.

CI runs this script on every change (inside [`test/e2e/e2e.sh`](../../test/e2e/e2e.sh),
which then exercises webhook denials, self-heal, ciphertext binding, recovery-key
rewrap to a replacement controller, the sealing UI and authenticated metrics).
