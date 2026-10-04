# Keyfold

**Recoverable, multi-recipient secrets for Kubernetes, stored encrypted in Git.**

Seal a secret once to every cluster that needs it and to an offline recovery
key. A controller in each cluster turns it into a `Secret`. Add or replace a
cluster without re-encrypting a single value. Lose a cluster, a controller or a
key — recover everything from the repository and any one remaining key. No
vault, no external store, no network hop in the decrypt path.

**New here? Read [docs/concepts.md](docs/concepts.md)** — the whole model on one
page: what is encrypted with what, who can do what, and what rewrap, rekey and
secret rotation each change.

## Why

- **Recoverable by design.** Each secret's content key is wrapped to several
  independent GPG recipients — cluster controllers, people, an offline recovery
  key. Any one of them can read it, and rewrap it to a replacement. Losing a key
  is a routine change, not an outage.
- **Add a cluster without re-encrypting anything.** Granting a new cluster
  access rewraps one small key per object; the encrypted values don't change.
  One command covers a whole directory.
- **Kubernetes-native, nothing to operate.** A CRD and a controller. Ciphertext
  lives inline in the object and arrives the way all your manifests do — your
  GitOps tool or `kubectl apply`. The controller never clones a repository or
  calls out.
- **Reviewable.** Who can decrypt (`spec.recipients`) and which commit a secret
  was sealed from are plain fields in the diff and columns in
  `kubectl get gitsecret`.
- **Honest limits.** Multi-recipient wrapping protects against *losing* keys,
  not against a *leaked* one — that takes rotating the secret itself. The
  [threat model](docs/security/threat-model.md) says exactly what is and isn't
  defended.

## How it looks

```bash
# seal to the cluster, the recovery key and yourself (recipients from a committed keyring)
keyfold seal --namespace prod --name db --keyring envs/prod/keyring.yaml \
  --from-env-file db.env > deploy/prod/db.yaml
git add deploy/prod/db.yaml && git commit -m "db credentials"   # ciphertext only

kubectl get gitsecret -n prod db           # synced into Secret/db by the controller

# add a second cluster to every prod secret — no value re-encrypted
keyfold recipients add <cluster-b-fpr> --role controller -f deploy/prod/ --write \
  --keyring envs/prod/keyring.yaml

# no cluster left at all? any one recipient key reads it back
keyfold unseal -f deploy/prod/db.yaml | jq .
```

## Install

**On Kubernetes** — the controller and CRD, from a Helm chart (signed images,
Pod Security `restricted`):

```bash
kubectl -n keyfold-system create secret generic keyfold-gpg --from-file=private.asc=controller.asc
helm install keyfold oci://ghcr.io/opscalehub/charts/keyfold \
  --namespace keyfold-system --set gpgPrivateKey.existingSecret=keyfold-gpg
```

**The CLIs** — from the [releases](https://github.com/OpScaleHub/keyfold/releases)
(linux/macOS amd64+arm64, windows amd64), each with SLSA provenance:

| Binary | For |
|---|---|
| `keyfold` | sealing, recipients, unseal, rekey, migrate — the main tool |
| `git-keyfold` | `git keyfold …`: encrypted files in a repository via git hooks |
| `kubectl-keyfold` | `kubectl keyfold …`: encrypted values inside a plain `Secret` manifest |

```bash
gh attestation verify ./keyfold-linux-amd64 --repo OpScaleHub/keyfold
```

Building from source needs Go 1.26+: `go install ./cmd/...` (binaries land in `$(go env GOPATH)/bin`).

Start with the **[Kubernetes quickstart](docs/getting-started/quickstart.md)**
(ten minutes, any cluster) — it ends by recovering the secret with no cluster at
all.

## Without Kubernetes

`git keyfold` encrypts whole files in a repository: you edit plaintext, Git
stores ciphertext, hooks keep it that way. Same envelope, its own key per
repository. See [getting started with the Git plugin](docs/getting-started/git-plugin.md).

## Documentation

| | |
|---|---|
| **Start** | [Concepts](docs/concepts.md) · [Kubernetes quickstart](docs/getting-started/quickstart.md) · [Git plugin](docs/getting-started/git-plugin.md) |
| **Operate** | [Multi-cluster](docs/architecture/multi-cluster.md) · [Recipient lifecycle](docs/security/recipient-lifecycle.md) · [Disaster recovery](docs/security/disaster-recovery.md) · [Troubleshooting](docs/guides/troubleshooting.md) · [Upgrading](UPGRADING.md) |
| **Reference** | [`keyfold` & the controller](docs/reference/keyfold.md) · [`git keyfold`](docs/reference/git-keyfold.md) · [`kubectl keyfold`](docs/reference/kubectl-keyfold.md) · [Helm chart](charts/keyfold/README.md) · [Keyring files](docs/architecture/keyring.md) |
| **Design** | [Architecture overview](docs/architecture/overview.md) · [Threat model](docs/security/threat-model.md) · [Decision records](docs/adr/) · [Design history](docs/security/design-rationale.md) |

All docs: [docs/README.md](docs/README.md).

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md), which also
covers verifying release signatures, provenance and SBOMs.

## Compatibility

[UPGRADING.md](UPGRADING.md) is the compatibility contract (the `v1alpha1` API
is additive-only) and includes the migration from the pre-rename
`git-secret` names — no re-encryption needed.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) · [GOVERNANCE.md](GOVERNANCE.md) ·
[Code of Conduct](CODE_OF_CONDUCT.md). Website:
[keyfold.opscale.ir](https://keyfold.opscale.ir).

## License

Intended to be MIT, but no `LICENSE` file has been committed yet — until it is
(tracked in [#129](https://github.com/OpScaleHub/keyfold/issues/129)), no
license is formally granted.
