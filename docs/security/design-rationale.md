# Design rationale & history

Why `git-secret` looks the way it does. This is a record of decisions, not a
roadmap. It replaces the `docs/adr/` set (ADR-0000/0001/0002), which was removed
once the `GitSecret` CRD became the single Kubernetes story; the reasoning in
those ADRs is preserved here because it is still the reason the architecture has
the shape it has.

## The one-sentence thesis

`git-secret` makes it safe to commit a secret to a Git repository: **ciphertext
is the durable source of truth in Git, and decryption is multi-recipient,
recoverable, and Kubernetes-native — without any single cluster, controller, or
key becoming a single point of catastrophic recovery failure.**

Everything below is in service of that sentence.

## How the Kubernetes integration evolved

The CLI + Git-hook workflow (encrypt on `pre-commit`, decrypt on
`post-checkout`/`post-merge`, block plaintext on `pre-push`) was the whole
project at first. Secrets were decrypted by hand (`make deploy-secrets`) or via a
documented-but-fragile ArgoCD Config Management Plugin. Making live secret
delivery to Kubernetes safe drove four successive designs:

### 1. ArgoCD CMP plugin — set aside

Worked, but routed decrypted plaintext through ArgoCD's own
manifest-generation/caching pipeline on every sync — a risk ArgoCD's own docs
call out. `selfHeal` also fights any out-of-band correction of a live `Secret`,
because ArgoCD's diff only sees "did the plugin's output change," not "is the
live value still correct."

### 2. Third-party secret store (Vault / Infisical / cloud) behind ESO — rejected

A new external dependency to stand up, secure, and operate. For an
Iran-hosted production target there is also a lived precedent for geo-blocking
breaking a dependency (`registry.k8s.io`), which for *live secret reconciliation*
is a worse outage than a blocked image pull. GitHub's own Secrets feature was
also considered and is structurally impossible as a backend — its API is
write-only by design, no credential can read a value back.

### 3. ESO webhook bridge (`git-secret-server`) — built, deployed, then superseded

A small stateless HTTP service behind [ESO's generic Webhook
provider](https://external-secrets.io/latest/provider/webhook/): clone the repo
fresh per request, decrypt in memory, return JSON. Bearer-token auth (constant
time, fails closed), bounded clone concurrency, a dedicated GPG identity separate
from the Git transport credential.

This validated several things worth keeping:

- Git can stay ciphertext-only; the repo credential and the decryption key are
  different things with different blast radii.
- Decryption is the only genuinely novel capability — secret *lifecycle*
  management is not worth owning.
- A long-lived network-reachable process holding a live decryption key is a real,
  reviewable attack surface (this is what the 25 closed findings in #1–#25 were
  about).

It also surfaced the problem that motivated the next design. ESO's provider model
assumes a remote store you *query*. `git-secret`'s data is ciphertext — it does
not need a store; it can be delivered as inert YAML by whatever already applies
manifests. Forcing it through ESO's Webhook provider meant: a full repo clone in
the cluster on every refresh interval for every consumer, an SSH transport and
known-hosts trust decision per clone (the security review confirmed a real
TOFU/`accept-new` gap with no fail-fast guard), and a five-layer delivery path
(ArgoCD → ESO CRDs → webhook → clone → decrypt) where several ordering / size /
retry-exhaustion failures showed up during the production rollout.

`git-secret-server` and its Helm chart still exist and still build. It is no
longer the recommended integration and receives no new feature work.

### 4. Native `GitSecret` CRD + controller — current

Bitnami `sealed-secrets`' shape — **ciphertext inline in a CRD object, delivered
by the normal manifest-apply path, decrypted by a controller holding a matching
private key** — applied to `git-secret`'s existing GPG-backed multi-recipient
cryptography instead of copying `sealed-secrets`' single-keypair design.

- `spec.encryptedKey` is the GPG-wrapped content key (same mechanism as the
  `gpg` file backend). `spec.encryptedData` holds one AEAD envelope per target
  key (same `crypto.Seal`/`crypto.Open` format as whole-file encryption).
- Reconciling a `GitSecret` makes **no network call**, clones nothing, and needs
  no SSH transport — the entire SSH-TOFU finding class does not exist on this
  path, structurally.
- **Multi-recipient from the start.** `spec.encryptedKey` can be wrapped to any
  number of recipients — the controller, plus independently any number of humans
  or offline backup identities. `internal/sealer.Rewrap` re-encrypts *only*
  `encryptedKey`, leaving every `encryptedData` value byte-for-byte untouched. A
  lost controller key is a `--rewrap` away from recovery via any other current
  recipient — not a permanent loss. This is the specific `sealed-secrets`
  weakness being designed out.
- `namespace/name/key` is bound into each value's AEAD additional-authenticated-
  data, so an entry copied into a different `GitSecret` (or a renamed one) fails
  authentication rather than decrypting where it was not sealed for.
- Built on `controller-runtime` (same as ESO, cert-manager, `sealed-secrets`) —
  the informer/reconcile/leader-election machinery is not worth hand-rolling.
- `git-secret-seal` is the `kubeseal` equivalent: produces a manifest from
  `--from-literal` / `--from-env-file` / an existing Secret, and rewraps an
  existing one's recipient list with `--rewrap`.

## What is deliberately foreclosed

Do not re-litigate these without genuinely new information:

- **GitHub Secrets as a backend** — structurally impossible (write-only API).
- **A third-party secret store as a *required* dependency** — an avoidable new
  operational and availability dependency. Nothing stops a future design adding
  one as an *optional* backend.
- **A decrypt endpoint on the controller** — conflates the seal and decrypt trust
  domains the CRD design keeps apart. (A *sealing*-only console is a different,
  narrower question — see the backlog.)

## What this project is not

Not Vault. Not a hosted secret manager. Not a password manager. Not a replacement
for GPG. Not an identity provider. Not coupled to ESO, ArgoCD, or any one Git
host. Still fully useful with no Kubernetes at all — the CLI + `gpg` backend is
the whole product for a team that just wants secrets in Git.
