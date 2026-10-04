# `kubectl keyfold` — per-value encryption in a Secret manifest

`git-keyfold` encrypts whole files — the right grain for a single-purpose
credential file, but the wrong grain for a Kubernetes `Secret` manifest that
bundles several unrelated credentials in one `stringData` map: rotating one
key means decrypting/re-encrypting all of them, and every re-encryption
produces a full-file diff since AEAD ciphers use a fresh nonce each time.

`kubectl-keyfold` is a companion `kubectl` plugin, built from the same source
tree, that encrypts **individual `stringData` values** instead of the whole
file, reusing the Git plugin's crypto core, configuration and key backends unchanged.

### Install

```bash
go build -o kubectl-keyfold ./cmd/kubectl-keyfold
sudo mv kubectl-keyfold /usr/local/bin/
```

Once `kubectl-keyfold` is on `PATH`, `kubectl` discovers it automatically and
`kubectl keyfold <verb>` works as a `kubectl` subcommand.

### Config: `k8s_secret_paths`

Opt specific manifests into per-value mode by listing them (explicit
repo-relative paths, not globs) in `.keyfold.yml`, independent of `patterns`:

```yaml
k8s_secret_paths:
  - "deploy/api-secrets.yaml"
k8s_plaintext_keys:            # optional: stringData keys allowed to stay
  deploy/api-secrets.yaml:     # plaintext in a given manifest, e.g. a
    - "PLAIN_NOTE"             # non-secret placeholder living alongside
                                # real credentials in the same map
```

`git-keyfold`'s `verify`/`pre-commit` enforce `k8s_secret_paths` the same as
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
| `encrypt-value -f FILE -k KEY` (value on stdin) | Emit a `repo-enc:v1:...` blob bound to that file, key, and the manifest's object identity, to paste into `stringData` by hand. `--value-file PATH` reads the plaintext from a file instead of stdin. `--allow-argv <value>` uses a bare CLI argument instead — leaves the value in shell history/process listings, so prefer stdin or `--value-file`. |

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
manifest — i.e. forgets to run it through `kubectl keyfold apply` — the
ciphertext strings get applied *as the literal secret values*. This fails
safe from a leak perspective (ciphertext isn't a secret leak) but breaks
the application silently: no credential leaked, just garbage values in a
real `Secret`. Watch for this if you're introducing `kubectl-keyfold` to a
team that's used to plain `kubectl`.

