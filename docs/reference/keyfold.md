# `keyfold` and the `GitSecret` controller — reference

`keyfold` produces and maintains `GitSecret` manifests; `keyfold-controller`
reconciles them into `Secret`s. Terms are defined in [concepts](../concepts.md);
the walkthrough is the [quickstart](../getting-started/quickstart.md).

Every fingerprint is a full 40/64-hex GPG fingerprint — short key IDs and
e-mail addresses are rejected, because they are ambiguous and resolved against
whatever happens to be in the local keyring. `gpg -K --with-colons` prints
yours. Commands that write a manifest print it on stdout; redirect to a **new**
file (`> new.yaml && mv new.yaml old.yaml`), never onto the input — the shell
truncates it first.

## Commands

| Command | Does | Needs |
|---|---|---|
| `keyfold seal` (or bare `keyfold`) | new manifest from values | recipients' public keys |
| `keyfold recipients list` | who can decrypt, with roles | nothing secret |
| `keyfold recipients add\|remove` | rewrap to a changed recipient list | one recipient's private key + every recipient's public key |
| `keyfold --rewrap` | rewrap to an explicit list | same |
| `keyfold rekey` | new content key, same values | same |
| `keyfold set KEY` | change or add one value | same |
| `keyfold unseal` | print the values | one recipient's private key |
| `keyfold migrate` | move manifests to the current API group | nothing secret |
| `keyfold ui` | web form for sealing | recipients' public keys |

Public keys can come from your GPG keyring or, for `seal`, `--rewrap`,
`recipients`, `rekey` and `set`, from `--keyring` entries carrying
`publicKey` — used for that run only, each verified to be exactly the key its
fingerprint names, never imported.

### `keyfold seal`

```bash
keyfold seal --namespace NS --name NAME \
  (--recipient FPR ... | --keyring FILE|URL) \
  [--from-literal K=V ...] [--from-env-file FILE] [-f secret.yaml] \
  [--target-name NAME] [--target-type TYPE] [--source-revision SHA | --no-provenance]
```

Values come from literals, a dotenv file, or an existing `Secret` manifest
(`data` or `stringData`; its namespace and name are the defaults). Sources
combine; later ones override keys. A literal lands in shell history — prefer
the file forms for real secrets. `--keyring` adds its fingerprints to the
recipients and records their roles in the
`keyfold.opscalehub.io/recipient-roles` annotation. Run inside a Git working
tree, `seal` stamps provenance (`source-revision` — `-dirty` if tracked files
are modified — and `source-repo`); see [provenance](../architecture/provenance.md).

### `keyfold recipients`

```bash
keyfold recipients list   -f PATH [-f PATH ...]
keyfold recipients add    FPR -f PATH [-f PATH ...] [--role ROLE] [--write|--dry-run] [--keyring SRC]
keyfold recipients remove FPR -f PATH [-f PATH ...] [--force]  [--write|--dry-run] [--keyring SRC]
```

`PATH` is a manifest, a directory (every single-document `GitSecret` under it),
or `-` (stdin). One manifest without `--write` prints the result; several files
or a directory need `--write` (in place, atomically per file) or `--dry-run`.
All files are computed first — if any one fails, nothing is written — and
objects already in the wanted state are counted, not changed. `remove` refuses
to drop the last recipient, or the last `recovery` one, without `--force`.
Roles: `human` (default), `controller`, `recovery`, `deprecated`.

Removing a recipient does not stop them reading a content key they already
unwrapped — follow with `rekey`; see
[concepts](../concepts.md#removing-someone-is-not-revoking-what-they-saw).

### `keyfold --rewrap`

```bash
keyfold --rewrap FILE --recipient FPR [--recipient FPR ...] [--keyring SRC] > new.yaml
```

Rewraps one object to exactly the given list (it **replaces** the list —
include everyone who should keep access). `recipients add|remove` is usually
more convenient.

### `keyfold rekey` and `keyfold set`

```bash
keyfold rekey -f FILE > new.yaml
printf %s "$NEW" | keyfold set KEY -f FILE > new.yaml     # or --value-file PATH
```

Both decrypt the object, re-encrypt **every** value under a fresh content key,
and wrap it to the object's current `spec.recipients`, keeping its target and
roles. `rekey` changes no value; `set` changes or adds one — read from stdin
or `--value-file`, never from the command line — and re-stamps provenance
(`--no-provenance` drops it instead).

### `keyfold unseal`

```bash
keyfold unseal -f FILE [--key KEY] [--format json|env] [--show]
```

Decrypts with whichever recipient key your keyring holds — disaster recovery
without a cluster. JSON by default (lossless), `--format env` for shell-quoted
`KEY='value'` lines, `--key` for one raw value without a trailing newline.
Stdout only; refuses to print to a terminal unless `--show`. If your keyring
holds no recipient key, the error lists the fingerprints and roles it is
wrapped to.

### `keyfold migrate`

```bash
keyfold migrate -f PATH [-f PATH ...] [--dry-run]
```

Rewrites manifests from the pre-rename `git-secret.opscalehub.io` group in
place — `apiVersion` and annotation keys only; comments, formatting and
ciphertext untouched; idempotent. See [UPGRADING.md](../../UPGRADING.md).

### `keyfold ui`

A local, public-key-only web form for producing manifests
(`http://127.0.0.1:8765`): it never decrypts, never touches a cluster, never
persists. The chart can run it in-cluster (`sealUi.enabled`) — see
[sealing-console.md](../architecture/sealing-console.md).

## The `GitSecret` object

```yaml
apiVersion: keyfold.opscalehub.io/v1alpha1
kind: GitSecret
metadata:
  name: db
  namespace: prod
  annotations:
    keyfold.opscalehub.io/recipient-roles: "<fpr>:controller,<fpr>:recovery"
    keyfold.opscalehub.io/source-revision: 4f2a1c9…
spec:
  encryptedKey: |            # the content key, GPG-wrapped to every recipient
    -----BEGIN PGP MESSAGE-----
    …
  encryptedData:             # one AEAD envelope per key, bound to prod/db/<key>
    DB_PASSWORD: UkVOQwER…
  recipients: [<fpr>, <fpr>, <fpr>]
  target:                    # optional
    name: db                 # default: metadata.name
    type: Opaque             # default
    adopt: false             # take over an existing Secret this object doesn't own
```

`kubectl get gitsecret` shows `Target`, `Ready`, `Keys` and `Recipients`
(`-o wide` adds `Revision`). Status mirrors the recipient list, the source
revision and the effective target name; conditions report `Synced`,
`UnsealFailed`, `TargetConflict` or `ApplyFailed`.

## The controller

- **Identity.** One dedicated GPG identity per cluster, never a person's key,
  supplied as a `Secret` (`--gpg-private-key-file` / `GPG_PRIVATE_KEY_FILE`),
  imported into an isolated `GNUPGHOME` at startup; the in-memory copy is
  zeroed. `keyfold-controller --gpg-private-key-file KEY --print-public-key`
  prints the fingerprint and public key; the chart can also serve or publish
  it ([keyring.md](../architecture/keyring.md)).
- **Reconcile.** Decrypts objects wrapped to its key — and only those — into
  the target `Secret`, which it owns: deleting the `GitSecret` deletes the
  `Secret`. A pre-existing `Secret` it doesn't own is left alone
  (`TargetConflict`) unless `spec.target.adopt` is set. If an object stops
  decrypting, the last good `Secret` is kept and the object reports
  `UnsealFailed`. No network calls, no repository access.
- **Admission webhook** (optional, `webhook.enabled`): rejects objects whose
  `spec.recipients` count disagrees with `encryptedKey`, and enforces a
  Namespace's `keyfold.opscalehub.io/required-recipients`. It never decrypts.
  See [admission-webhook.md](../architecture/admission-webhook.md).
- **Health.** Ready while the apiserver answers and the cache has synced;
  `/metrics` is HTTPS with TokenReview/SubjectAccessReview by default.

Install with the Helm chart ([chart README](../../charts/keyfold/README.md)).
For local development: `go build ./cmd/keyfold ./cmd/keyfold-controller`.
