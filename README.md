# Git Secret Manager (`git-secret`)

`git-secret` is a single-binary Git plugin that transparently encrypts sensitive files in a repository. You keep working with plaintext in your working tree; the installed git hooks make sure only ciphertext ever reaches your commit history.

## Features

- **Transparent encryption**: git hooks (`pre-commit`, `post-checkout`, `post-merge`, `pre-push`) encrypt/decrypt automatically as you commit, checkout, merge, and push — no manual encrypt/decrypt step in the common case.
- **Modern AEAD crypto**: XChaCha20-Poly1305 by default (AES-256-GCM available) does the actual file encryption either way — GPG is never in that path, so `file`/`env` need no GPG dependency at all.
- **Config-driven**: glob `patterns` in a committed `.repo-enc.yml` decide which files are in scope; everything else is left untouched.
- **Pluggable key backends**: `file` (a local, gitignored key file), `env` (an environment variable), or `gpg` (wraps the key to one or more existing GPG identities — safe to commit, no out-of-band key transfer needed). The `Backend` interface makes adding KMS backends straightforward too.
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
git secret init                 # writes .repo-enc.yml, generates a key, installs hooks
git add .repo-enc.yml .gitignore
git commit -m "chore: configure repo-enc"
```

`.repo-enc.yml` must be committed — it's how a teammate's clone knows which
patterns to encrypt/decrypt. The generated key must **not** be committed
(`init` already gitignores it for the `file` backend); share it with
collaborators out-of-band instead.

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

- **`file`** (default): a 32-byte key stored as hex in `key_source` (default `.repo-enc/key`), gitignored automatically by `init`. Giving a teammate access means copying this raw key to them out-of-band.
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
manifest — i.e. forgets the plugin — the ciphertext strings get applied *as
the literal secret values*. This fails safe from a leak perspective
(ciphertext isn't a secret leak) but breaks the application silently: no
credential leaked, just garbage values in a real `Secret`. Watch for this if
you're introducing `kubectl-secret` to a team that's used to plain `kubectl`.

### ArgoCD integration (Config Management Plugin)

The footgun above is worse under GitOps specifically: if ArgoCD applies the
encrypted manifest directly, it doesn't just break the app once — it
actively **fights** anything that later corrects the live `Secret` by hand.
`selfHeal` will keep reverting the live object back to ciphertext on every
reconcile, since as far as ArgoCD's diffing is concerned, the ciphertext
*is* the desired state. Worse, a live secret that's fixed out-of-band (a
quick `kubectl patch` during an incident, say) and never sealed back into
the file will silently drift from git with no warning — the exact gap that
motivated this integration in the first place.

The fix is to make ArgoCD decrypt as part of its own sync, via a [Config
Management Plugin](https://argo-cd.readthedocs.io/en/stable/user-guide/config-management-plugins/)
(CMP) sidecar on `argocd-repo-server`, so a drifted live value shows up as
ordinary `OutOfSync` — the same signal ArgoCD already gives you for a
drifted `Deployment` — instead of failing silently.

> **This is manifest-generation secret injection, with the risks ArgoCD's
> own docs describe.** A CMP `generate` command that emits decrypted
> `Secret` YAML means the plugin's output stream — the *fully decrypted*
> manifest — flows through ArgoCD's normal generated-manifest pipeline,
> where ArgoCD's [secret management
> docs](https://argo-cd.readthedocs.io/en/stable/operator-manual/secret-management/#argo-cd-manifest-generation-based-secret-management)
> say it can be cached in Redis and is reachable by anyone with repo-server
> API access — not just anyone with `kubectl get secret` on the cluster.
> Read their [mitigation
> guidance](https://argo-cd.readthedocs.io/en/stable/operator-manual/secret-management/#mitigating-risks-of-secret-injection-plugins)
> before adopting this pattern for anything sensitive, and prefer a
> destination-cluster secret management approach (e.g. decrypting outside
> ArgoCD entirely, so the repo-server never holds the key or the plaintext)
> wherever that's an option. What follows documents the CMP pattern as-is,
> not as an endorsement that it's the safest option available.

**1. Register the plugin.** A `ConfigMap` mounted into the sidecar at
`/home/argocd/cmp-server/config/plugin.yaml`:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ConfigManagementPlugin
metadata:
  name: kubectl-secret
spec:
  version: v1.0
  generate:
    command: ["sh", "-c"]
    args:
      - "mkdir -p .repo-enc && rm -f .repo-enc/key && cp /repo-enc-key/key .repo-enc/key && kubectl-secret view -f secrets.enc.yaml"
```

The `mkdir`/`cp` prefix isn't optional. `generate.command` runs with `CWD`
set to a fresh, per-sync ephemeral checkout directory
(`/tmp/_cmp_server/<uuid>/`), not a fixed path — so a `key_backend: file`
key mounted at a stable absolute path (via a `Secret` volume, see below)
has to be staged into the repo-relative location `key_source` expects
(`.repo-enc/key` by default) before every single invocation.

The `rm -f .repo-enc/key` immediately before `cp` isn't optional either.
`CWD` here is the *repo checkout* — attacker-controlled content, from
ArgoCD's point of view, if anyone can land a commit — so a committed
symlink at `.repo-enc/key` (e.g. pointing at `/proc/self/fd/1` to print
the raw key into plugin output, or elsewhere in the pod filesystem) would
otherwise make `cp` follow it and write the decryption key wherever that
symlink points, instead of to a fresh regular file. `rm -f` unlinks
whatever is currently at that path — symlink or not, without following
it — so `cp` always creates a clean regular file afterward.

**2. Add the sidecar.** Same pattern as any other CMP: a sidecar container
on `argocd-repo-server` running `argocd-cmp-server` against that plugin
config, plus an initContainer to fetch the `kubectl-secret` binary itself
into a shared `emptyDir`. **Verify the checksum before executing it** —
release binaries are unsigned, so this at least confirms the download
matches what CI built and published, rather than trusting an unauthenticated
`curl | chmod +x` sight unseen for a binary that will hold the repo's
decryption key:

```yaml
initContainers:
  - name: kubectl-secret-install
    image: curlimages/curl:8.10.1
    command: ["sh", "-c"]
    args:
      - |
        set -eu
        cd /kubectl-secret-bin
        curl -sSL -O https://github.com/OpScaleHub/git-secret/releases/download/v0.4.1/kubectl-secret-linux-amd64
        curl -sSL -O https://github.com/OpScaleHub/git-secret/releases/download/v0.4.1/kubectl-secret-linux-amd64.sha256
        sha256sum -c kubectl-secret-linux-amd64.sha256
        mv kubectl-secret-linux-amd64 kubectl-secret
        chmod +x kubectl-secret
    volumeMounts:
      - {mountPath: /kubectl-secret-bin, name: kubectl-secret-bin}
containers:
  - name: kubectl-secret-cmp
    command: [/var/run/argocd/argocd-cmp-server]
    image: quay.io/argoproj/argocd:v3.4.5   # match your ArgoCD's own version
    env:
      - {name: PATH, value: "/kubectl-secret-bin:/usr/local/bin:/usr/bin:/bin"}
    securityContext: {runAsNonRoot: true, runAsUser: 999}
    volumeMounts:
      - {mountPath: /var/run/argocd, name: var-files}              # existing
      - {mountPath: /home/argocd/cmp-server/plugins, name: plugins} # existing
      - {mountPath: /home/argocd/cmp-server/config/plugin.yaml, subPath: plugin.yaml, name: kubectl-secret-cmp-config}
      - {mountPath: /tmp, name: cmp-tmp}
      - {mountPath: /kubectl-secret-bin, name: kubectl-secret-bin}
      - {mountPath: /repo-enc-key, name: repo-enc-key, readOnly: true}
```

`var-files` and `plugins` are volumes `argocd-repo-server` already has for
its own built-in plugin support — reuse them rather than adding new ones.
`repo-enc-key` is a new `Secret` volume holding the raw key file content
(`key_backend: file`'s `key_source`) — this is the one genuinely sensitive
step: it moves the decryption key from your local machine into the
cluster. Scope that `Secret` narrowly (the `argocd` namespace only) and
treat adding it with the same care as any other production credential
write.

**3. Point an Application at it.** A second `Application`, separate from
your main one, with its source path wherever `secrets.enc.yaml` lives
(often the repo root) and `spec.source.plugin.name` set to
`<plugin-metadata-name>-<version>` — note the concatenation; the CMP
server logs the exact string it registered under
(`argocd-cmp-server ... serving on .../kubectl-secret-v1.0.sock`) if
you're unsure:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app-secrets
spec:
  source:
    repoURL: git@github.com:you/your-repo.git
    targetRevision: stable
    path: .
    plugin:
      name: kubectl-secret-v1.0
  syncPolicy:
    automated: {selfHeal: true}   # the whole point -- see above
```

Keep this `Application` separate from whatever manages the rest of your
manifests, and make sure **exactly one** of them owns the resulting
`Secret` object. If your main app's source also happens to include a
plaintext/placeholder version of the same `Secret` (a common leftover from
before adopting per-value encryption), exclude it there — two ArgoCD
`Application`s both claiming the same live object will fight every
reconcile, each reverting the other's last write.

## Publishing & GitHub Pages

The project website is published at: [https://git-secret.opscale.ir](https://git-secret.opscale.ir)

## License

MIT License. See [LICENSE](LICENSE) for details.
