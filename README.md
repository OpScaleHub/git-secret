# Git Secret Manager (`git-secret`)

**A recoverable, Git-native cryptographic control plane for Kubernetes secrets.**

The encrypted Git repository is the durable source of truth. Decryption is
multi-recipient, auditable, and Kubernetes-native — and no single cluster,
controller, or key is a single point of catastrophic recovery failure. It is also
a plain single-binary Git plugin: transparent file encryption via git hooks, with
plaintext only ever in your working tree, never in commit history.

### Design goals

1. No single controller key is a single point of unrecoverable failure.
2. Losing Kubernetes does not lose the secrets.
3. Git history stays a useful, durable encrypted record.
4. Multiple humans and services decrypt independently.
5. Kubernetes receives plaintext only at the final reconcile boundary.
6. The controller is a *consumer* of the encrypted source, not its owner.
7. Metadata is observable; plaintext never is.
8. Recovery is possible entirely outside the cluster.
9. Recipient identity is an explicit GPG fingerprint.
10. Still fully useful with no Kubernetes at all (the CLI + `gpg` backend).

### What it is not

Not Vault, not a hosted secret manager, not a password manager, not a GPG
replacement, not an identity provider — and not coupled to ESO, ArgoCD, or any
one Git host.

### Compared to

| | `git-secret` | Bitnami sealed-secrets | SOPS | Vault |
|---|---|---|---|---|
| Ciphertext lives in Git | yes | yes | yes | no (external store) |
| Survives loss of the cluster/controller key | **yes** (multi-recipient) | no (single keypair) | yes | n/a |
| Kubernetes-native reconcile | yes (CRD + controller) | yes | via operator | via ESO/agent |
| Useful with no Kubernetes | yes (CLI) | no | yes | no |
| External service to operate | no | no | no | yes |

See [docs/security/design-rationale.md](docs/security/design-rationale.md) for how
the architecture got here.

## Features

- **Transparent encryption**: git hooks (`pre-commit`, `post-checkout`, `post-merge`, `pre-push`) encrypt/decrypt automatically as you commit, checkout, merge, and push — no manual encrypt/decrypt step in the common case.
- **Modern AEAD crypto**: XChaCha20-Poly1305 by default (AES-256-GCM available) does the actual file encryption either way — GPG is never in that path, so `file`/`env` need no GPG dependency at all.
- **Config-driven**: glob `patterns` in a committed `.repo-enc.yml` decide which files are in scope; everything else is left untouched.
- **Pluggable key backends**: `gpg` (wraps the key to one or more existing GPG identities — safe to commit, no out-of-band transfer, and the only backend that works with automated consumers or survives the loss of a single key — **recommended**), `file` (a local, gitignored key file — quick start, local/solo only), or `env` (an environment variable). The `Backend` interface makes adding KMS backends straightforward too.
- **Safety net**: `verify` and the `pre-push` hook refuse to let plaintext that slipped past `pre-commit` (e.g. via `--no-verify`) reach a remote.
- **Cross-platform**: pure Go, no runtime dependencies beyond `git` itself (`gpg` is an optional extra, only needed if you choose that backend). Installed hooks ship as both POSIX shell and PowerShell scripts.

## Requirements

- **Go** 1.25 or newer (for building from source)
- **Git** (for hooks, config discovery, and blob storage)

## Installation

### Build from source

```bash
git clone https://github.com/OpScaleHub/git-secret.git
cd git-secret
go build -o git-secret .
sudo mv git-secret /usr/local/bin/
```

On Windows, build with the `.exe` extension explicitly (Go does not add it
for you) and put the result on `PATH`:

```powershell
go build -o git-secret.exe .
```

Once `git-secret` is on your `PATH`, `git secret <command>` works as a git subcommand.

## Quick start

```bash
cd your-repo

# Recommended for any team, and required for Kubernetes/CI: the gpg backend,
# with every human AND every service that needs access as its own recipient.
git secret init --key-backend gpg \
  --gpg-recipient <your-fingerprint> --gpg-recipient <teammate-fingerprint>
git add .repo-enc.yml .repo-enc/key.gpg .gitignore
git commit -m "chore: configure repo-enc"
```

**Which backend?** `gpg` (above) is the only one that works with
`git-secret-controller` or any automated consumer, and the only one where losing
one key doesn't threaten recoverability — its wrapped key is safe to commit, no
out-of-band key transfer. The `file` backend (`git secret init` with no
`--key-backend`) is a quick local/solo on-ramp, but its key never enters git, so
adopting Kubernetes or CI later forces a full re-seal. Start on `gpg` unless you
are certain automation will never be in scope.

```bash
git secret init                 # 'file' backend: quick start, local/solo only
```

`.repo-enc.yml` must be committed — it's how a teammate's clone knows which
patterns to encrypt/decrypt. For the `file` backend the generated key must
**not** be committed (`init` gitignores it); share it out-of-band. For `gpg`,
`.repo-enc/key.gpg` **is** committed and no key transfer is needed.

By default `init` seeds `.repo-enc.yml` with the pattern `secrets/**`. Pass your own patterns instead:

```bash
git secret init "secrets/**" "*.secret.env"
```

From here, just use git normally:

```bash
echo "password: hunter2" > secrets/db.yaml
git add secrets/db.yaml
git commit -m "add db credentials"   # pre-commit hook encrypts what's staged;
                                      # your working copy of secrets/db.yaml stays plaintext
```

`git log -p` / `git show` on that commit show ciphertext. `cat secrets/db.yaml` on disk still shows plaintext. That's the point.

When someone else clones the repo, their working tree gets ciphertext (that's what's committed). They need the repo's key transferred out-of-band (it's gitignored, never committed) before `post-checkout`/`unlock` can decrypt it for them.

## Commands

| Command | Effect |
|---|---|
| `init [pattern...]` | Bootstrap: write `.repo-enc.yml` (idempotent), generate a key if missing, install hooks. |
| `status` | Show which config-matched files are plaintext vs encrypted in the working tree right now. |
| `lock` | Encrypt every config-matched file in place — end of session. |
| `unlock` | Decrypt every config-matched file in place — start of session. Marks each file `skip-worktree` so `git status` stays quiet while you view them (see below). |
| `encrypt <path...>` | Encrypt specific files in place. |
| `decrypt <path...>` | Decrypt specific files in place. |
| `rotate-keys` | Generate a new key and re-encrypt every config-matched file under it. |
| `verify` | Check every config-matched file and `k8s_secret_paths` manifest committed at `HEAD` is actually, authentically encrypted (and that the raw `file`-backend key isn't committed); exits 3 if not. Requires the key — it fails closed (exit 2) rather than skip the one check that proves anything. |
| `adduser [recipient]` | `gpg` backend only: grant a recipient access — cheap, re-wraps the existing key without touching any file. Omit the argument to pick interactively from your local public keyring. |
| `removeuser <recipient>` | `gpg` backend only: revoke a recipient and rotate to a brand new key — a removed recipient already saw the old one, so this re-encrypts every matched file. |
| `hook <name>` | Internal — invoked by the installed hooks, not typically run by hand. |
| `version` | Show version, commit, and Go runtime info. |

Exit codes: `0` ok · `1` generic error · `2` key unavailable · `3` `verify` found plaintext in history.

CI note: set `SECRETIZE_SKIP_HOOKS=1` to make every installed hook exit 0 immediately without running. This is deliberately not tied to the ambient `CI` variable — every CI provider, IDE, and automation wrapper sets `CI=1` by convention, so honoring it implicitly would silently disable both encryption and push-protection in exactly the environments most likely to push on someone's behalf. Opt out explicitly, per invocation.

### `unlock` and `git status`

`unlock` marks each decrypted file `skip-worktree`, so `git status`/`git diff` won't flag it as modified just because you're viewing it locally with plaintext on disk while the index holds ciphertext (that divergence is intentional — see "How it works" below). `lock` clears the flag again.

If you edit an unlocked file and want to commit the change, **run `git secret lock` before `git add`** — this isn't just tidiness: recent git versions refuse a plain `git add` on a `skip-worktree`'d path outright (with a confusing sparse-checkout-flavored error, even in repos that never touched sparse-checkout), and `commit -a`/`commit <path>` silently see no change at all, since `skip-worktree` tells git's own diff machinery there's nothing there to look at. `git secret lock` sidesteps this entirely — it reads the current working-tree content directly (not through `git add`), re-encrypts it, and clears the flag itself, so the `git add`/`git commit` that follows behaves normally. The supported edit flow is: `unlock` → edit → `lock` → `git add` → `git commit` (as usual — `pre-commit` sees the content is already encrypted and just commits it).

**`git pull`/`git merge` while a file is unlocked.** A clean pull (nobody touched that file upstream) works fine and refreshes the file normally. But if a teammate changes the *same* file you currently have unlocked, `git pull` will refuse with git's standard `Your local changes to the following files would be overwritten by merge` error — `skip-worktree` suppresses `status`/`diff` reporting, but not git's real uncommitted-change protection during a merge, and there's no pre-pull hook available to handle this automatically. If you hit this on a file you were only viewing (not editing), the safe recovery is:

```bash
git secret lock                                    # your local view becomes disposable ciphertext
SECRETIZE_SKIP_HOOKS=1 git checkout -- <path>      # discard it back to what's committed
git pull                                            # now safe — post-merge decrypts the new content
```

The `SECRETIZE_SKIP_HOOKS=1` matters: `git checkout -- <path>` fires the `post-checkout` hook even for a single-file restore in current git, which would otherwise immediately re-decrypt what checkout just restored and put you right back in the same diverged, pull-blocking state. If you *were* genuinely editing that file, don't discard it — this is then a real merge conflict like any other and needs manual resolution (commit or stash your change first).

## Configuration (`.repo-enc.yml`)

Committed at the repo root:

```yaml
version: 1
patterns:
  - "secrets/**"
  - "*.secret.env"
exclude:
  - "secrets/public/**"
key_backend: file          # file | env | gpg
key_source: .repo-enc/key  # path (file/gpg backends) or env var name (env backend)
gpg_recipients:            # gpg backend only — GPG fingerprints, not secret
  - AAAABBBBCCCCDDDD1111222233334444AAAABBBB
```

`patterns`/`exclude` are glob paths relative to the repo root (a leading `/` is accepted and normalized away — `/secrets/**` and `secrets/**` are the same pattern); `**` matches any depth. A machine-local `~/.config/repo-enc/config.yml` (or the OS equivalent — set `REPO_ENC_CONFIG_DIR` to override the directory outright, e.g. for containers/CI) can set personal defaults — `key_backend`/`key_source` there apply unless the repo config overrides them, and `patterns`/`gpg_recipients`/`k8s_secret_paths` entries there are unioned with the repo's, since those can only *expand* what's protected. `exclude` and `k8s_plaintext_keys` are the opposite — both can only *shrink* protection — so they're taken from the repo config alone; a global config can never silently carve a hole out of a repo's committed policy.

### Key backends

**Use `gpg` for anything beyond a solo local repo** — it is the only backend that works with `git-secret-controller` or any automated consumer, and the only one where losing a single key doesn't threaten recoverability. `init` prints a nudge when it falls back to `file`.

- **`file`** (default): a 32-byte key stored as hex in `key_source` (default `.repo-enc/key`), gitignored automatically by `init`. Giving a teammate access means copying this raw key to them out-of-band. Structurally incompatible with automated decryption — the key never enters git.
- **`env`**: the key is read from the environment variable named by `key_source`. `init`/`rotate-keys` print an `export VAR=<hex>` line when they generate a new one — this backend can't persist anything to disk for you, so copy that value down before the process exits.
- **`gpg`**: the same random 32-byte key, but wrapped (GPG-encrypted) to one or more recipients instead of stored raw. The wrapped blob (default `.repo-enc/key.gpg`) is **safe to commit** — unlike the `file` backend's key — since only a matching GPG private key can unwrap it. This solves the onboarding pain point above: a teammate who's already a configured recipient just needs `git secret init` (installs hooks; the committed config already has everything else) and their own existing keyring does the rest, no manual key transfer required.

  ```bash
  git secret init --key-backend gpg                      # picks interactively from your local GPG keys
  git secret init --key-backend gpg --gpg-recipient <fpr> # or specify one directly (repeatable), e.g. for CI

  git secret adduser <teammate-fingerprint>   # cheap: re-wraps the existing key, no file re-encryption
  git secret removeuser <fingerprint>         # forces a full rotate-keys — the removed person already saw the old key
  ```

  Both `adduser`/`removeuser` require `key_backend: gpg` and error otherwise. `status` additionally lists current recipients for this backend.

  **CI/automation caveat**: `gpg --decrypt`/`--encrypt` may need gpg-agent/pinentry, which isn't available in a non-interactive session (CI, hooks with no TTY). Either keep a passphrase-less secret key in a CI-local ephemeral keyring, or prefer `env`/`file` for CI and reserve `gpg` for interactive developer machines.

## How it works

- **`pre-commit`**: for each staged, pattern-matched file, encrypts the *staged* content and repoints the git index at the ciphertext blob (`git hash-object` + `git update-index --cacheinfo`) — your working-tree file is never touched.
- **`post-checkout` / `post-merge`**: decrypts pattern-matched working-tree files that checkout/merge just populated with ciphertext, if a key is available. Missing key ⇒ warns, doesn't fail the checkout.
- **`pre-push`**: runs the same authenticated check as `verify` against `HEAD`, *and* walks every commit actually being pushed (reading git's ref-update protocol from stdin) that the remote doesn't already have, so a plaintext commit earlier in the range can't reach the remote just because a later commit fixed `HEAD`. The range walk validates envelope structure rather than fully authenticating (a commit deep in history may be sealed under a since-rotated key that the current key can no longer open), which is still enough to catch content that was never encrypted at all.
- **`rotate-keys`**: decrypts every matched file under the current key, re-encrypts under a freshly generated one, and only writes anything to disk once every file has round-tripped successfully in memory — a failure partway through never leaves you with an unrecoverable file.

See `examples/basic/` for a runnable walkthrough.

## kubectl-secret

`git-secret` encrypts whole files — the right grain for a single-purpose
credential file, but the wrong grain for a Kubernetes `Secret` manifest that
bundles several unrelated credentials in one `stringData` map: rotating one
key means decrypting/re-encrypting all of them, and every re-encryption
produces a full-file diff since AEAD ciphers use a fresh nonce each time.

`kubectl-secret` is a companion `kubectl` plugin, built from the same source
tree, that encrypts **individual `stringData` values** instead of the whole
file, reusing `git-secret`'s crypto core and key backends unchanged.

### Install

```bash
go build -o kubectl-secret ./cmd/kubectl-secret
sudo mv kubectl-secret /usr/local/bin/
```

Once `kubectl-secret` is on `PATH`, `kubectl` discovers it automatically and
`kubectl secret <verb>` works as a `kubectl` subcommand.

### Config: `k8s_secret_paths`

Opt specific manifests into per-value mode by listing them (explicit
repo-relative paths, not globs) in `.repo-enc.yml`, independent of `patterns`:

```yaml
k8s_secret_paths:
  - "deploy/api-secrets.yaml"
k8s_plaintext_keys:            # optional: stringData keys allowed to stay
  deploy/api-secrets.yaml:     # plaintext in a given manifest, e.g. a
    - "PLAIN_NOTE"             # non-secret placeholder living alongside
                                # real credentials in the same map
```

`git-secret`'s `verify`/`pre-commit` enforce `k8s_secret_paths` the same as
whole-file `patterns`: any `stringData` value that's neither a `repo-enc:v1:`
blob nor listed in `k8s_plaintext_keys` is treated as an accidentally-leaked
secret and blocks the commit/fails verification — not just an all-or-nothing
"is *everything* plaintext" check, so one unencrypted value sitting next to
several real ciphertext ones is still caught.

### Verbs

| Verb | Effect |
|---|---|
| `apply -f FILE [-n NAMESPACE]` | Decrypt matched `stringData` values in memory and `kubectl apply` the result. Never writes plaintext to disk. Warns if the object carries an `argocd.argoproj.io/instance` label (see ArgoCD footgun below). |
| `create -f FILE [-n NAMESPACE]` | Same, but `kubectl create`. |
| `view -f FILE` | Print the fully-decrypted manifest to stdout. Never writes it to disk. |
| `encrypt-value -f FILE -k KEY` (value on stdin) | Emit a `repo-enc:v1:...` blob bound to that file, key, and the manifest's object identity, to paste into `stringData` by hand. `--allow-argv <value>` uses a bare CLI argument instead — leaves the value in shell history/process listings, so prefer stdin. |

A value is ciphertext if it starts with `repo-enc:v1:`; anything else is left
untouched, so plaintext and ciphertext values coexist freely in the same
`stringData` map — only encrypt the keys that are actually secret.

**Ciphertext is bound to the object it lives in**, not just the file and key:
`encrypt-value` reads `apiVersion`/`kind`/`metadata.name`/`metadata.namespace`
from `FILE` (which must already declare them) and folds them into the seal.
Moving valid ciphertext into a manifest with a different name or namespace —
or an `apply -n` that targets a namespace the value wasn't sealed for — fails
to decrypt instead of silently authenticating onto the wrong object. YAML
anchors on an encrypted `stringData` value are rejected outright, since
decrypting would copy the plaintext into every place in the document that
aliases it (`stringData` is write-only in Kubernetes; an aliased annotation
elsewhere isn't).

v1 scope: `stringData` only (not `data`, which is base64-encoded — a marker
placed there would itself look like valid base64 and silently decode to
garbage rather than failing loudly), and single-document manifests (no `---`
multi-doc files).

### The footgun this doesn't fully solve

If someone runs plain `kubectl apply -f file.yaml` on a per-value-encrypted
manifest — i.e. forgets to run it through `kubectl secret apply` — the
ciphertext strings get applied *as the literal secret values*. This fails
safe from a leak perspective (ciphertext isn't a secret leak) but breaks
the application silently: no credential leaked, just garbage values in a
real `Secret`. Watch for this if you're introducing `kubectl-secret` to a
team that's used to plain `kubectl`.

## GitSecret CRD (git-secret-controller)

`kubectl-secret` (above) is a human/CI-driven tool: someone runs `apply`/`view`
by hand. `GitSecret` is a native custom resource
(`git-secret.opscalehub.io/v1alpha1`) with its own controller instead, whose
ciphertext lives **inline in the object itself** — no repo clone, no SSH
transport, no network hop at all in the decrypt path. Delivered by whatever
already applies manifests to your cluster (ArgoCD, `kubectl apply`, ...), the
same way any other Kubernetes object gets there. Modeled on Bitnami
`sealed-secrets`' shape, but built on `git-secret`'s existing multi-recipient
GPG cryptography instead of a single controller keypair — a lost or rotated
controller key is a `--rewrap` away from recovery via any other current
recipient, not a permanent loss.

```bash
# Seal plaintext into a GitSecret manifest (the kubeseal equivalent):
git-secret-seal --namespace myapp --name my-secrets \
  --recipient <controller-fingerprint> --recipient <your-own-fingerprint> \
  --from-literal API_KEY=... --from-literal DB_PASSWORD=... > gitsecret.yaml

kubectl apply -f gitsecret.yaml   # git-secret-controller reconciles it into a plain Secret

# Add/remove a recipient later without re-encrypting any value:
git-secret-seal recipients add <new-fingerprint> -f gitsecret.yaml --role recovery
git-secret-seal recipients remove <old-fingerprint> -f gitsecret.yaml
git-secret-seal recipients list -f gitsecret.yaml       # who can decrypt, and their role

# ...or set the whole list explicitly:
git-secret-seal --rewrap gitsecret.yaml \
  --recipient <controller-fingerprint> --recipient <your-own-fingerprint> --recipient <new-fingerprint>

# ...or resolve recipients from a committed keyring file instead of typing them:
git-secret-seal --namespace myapp --name my-secrets \
  --keyring envs/prod/keyring.yaml --from-env-file app.env > gitsecret.yaml
```

Get the controller's own fingerprint + public key with
`git-secret-controller --gpg-private-key-file <key> --print-public-key`. See
[docs/architecture/keyring.md](docs/architecture/keyring.md) for the keyring
format and per-environment layout.

The generated manifest records the fingerprints it was sealed to in
`spec.recipients`, so adding or removing a recipient shows up as a one-line
change in review rather than an opaque blob churn. The controller mirrors this
to `status.recipients` / `status.recipientCount` (a `Recipients` column on
`kubectl get gitsecret`) so you can see who can decrypt an object without
inspecting the ciphertext.

Every `--recipient` must be a full 40/64-hex GPG fingerprint, not a short key
ID or an email address — `git-secret-seal` rejects anything else, the same
rule `.repo-enc.yml`'s `gpg_recipients` already enforces (see
[`gpgutil.ValidFingerprint`](internal/gpgutil/gpgutil.go)'s doc comment for
why: a short ID or email is ambiguous and locally resolvable, a fingerprint
isn't). `gpg --list-secret-keys --with-colons` (or `gpg -K`) prints yours.

The controller owns the target `Secret` it creates (deleting the `GitSecret`
deletes the `Secret`). If a `Secret` with the target name already exists and is
*not* managed by this `GitSecret`, the controller leaves it untouched and sets a
`TargetConflict` condition rather than clobbering it — set `spec.target.adopt:
true` to deliberately take it over.

An optional **validating admission webhook** (`webhook.enabled` in the chart)
rejects a `GitSecret` whose `spec.recipients` disagrees with its `encryptedKey`,
and enforces a per-namespace required-recipient set
(`git-secret.opscalehub.io/required-recipients` on the `Namespace`). It manages
its own self-signed cert — no cert-manager. See
[docs/architecture/admission-webhook.md](docs/architecture/admission-webhook.md).

`git-secret-controller` needs its own dedicated GPG identity, imported at
startup into an isolated `GNUPGHOME`
(`--gpg-private-key-file`/`GPG_PRIVATE_KEY_FILE`, key zeroed from memory
once imported). Install the CRD from
`config/crd/bases/git-secret.opscalehub.io_gitsecrets.yaml` before running
the controller.

A container image and Helm chart ship on every tagged release
(`charts/git-secret-controller`). For local work, build the binaries with
`go build ./cmd/git-secret-controller` and `go build ./cmd/git-secret-seal`.

## Security

- [Threat model](docs/security/threat-model.md) — assets, trust boundaries,
  threats, and the invariants the code must preserve.
- [Design rationale & history](docs/security/design-rationale.md) — why the
  architecture has the shape it has.
- [Architecture overview](docs/architecture/overview.md) — ASCII diagrams of the
  seal → apply → reconcile flow, the two-layer envelope, and the recovery model.
- [Disaster recovery](docs/security/disaster-recovery.md) — operator runbooks for
  controller loss, cluster loss, key loss, and key compromise.
- [Recipient & key lifecycle](docs/security/recipient-lifecycle.md) — roles,
  rotation workflows, and what removing a recipient does and doesn't undo.
- [Multi-cluster operation](docs/architecture/multi-cluster.md) — one encrypted
  repo, per-cluster controller identities, no central store.
- [Cluster keyring](docs/architecture/keyring.md) — `--print-public-key`,
  `git-secret-seal --keyring`, per-environment recipient sets.
- [Reporting a vulnerability](SECURITY.md).

The core property: the encrypted repository is the durable source of truth, and
decryption is multi-recipient and recoverable.

> Losing the Kubernetes cluster does not mean losing the secrets, as long as the
> Git repository and one authorized recipient private key survive.

Multi-recipient GPG protects against *loss* of a key. Recovering from a *compromised*
key additionally requires rotating the secret values themselves — see the disaster
recovery guide.

## Publishing & GitHub Pages

The project website is published at: [https://git-secret.opscale.ir](https://git-secret.opscale.ir)

## License

MIT License. See [LICENSE](LICENSE) for details.
