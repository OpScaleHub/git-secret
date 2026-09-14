# Troubleshooting

Every error string and exit code below was reproduced against the actual
CLI/controller while writing this doc, not guessed from reading the code.

## Exit codes (`git-secret`, `kubectl-secret`)

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | generic error (bad usage, config error, GPG recipient rejected, ...) |
| `2` | key unavailable — the backend's key file/env var/GPG secret key couldn't be found or opened |
| `3` | `verify` (or `pre-push`'s equivalent check) found plaintext committed at `HEAD` |

## "verify found plaintext committed at HEAD"

```
$ git secret verify
verify: found plaintext committed at HEAD for:
  secrets/db.yaml: crypto: not a recognized encrypted file (bad magic)
```

**Cause:** a config-matched file (or a `k8s_secret_paths` manifest value)
reached a commit without going through encryption — usually `git commit
--no-verify`, or a file added to `patterns`/`k8s_secret_paths` *after* it was
already committed as plaintext.

**Fix:**

```bash
git secret lock          # encrypt the current working-tree content in place
git add secrets/db.yaml
git commit -m "fix: encrypt secrets/db.yaml"
git secret verify         # confirm: exit 0
```

`verify` deliberately checks the committed tree at `HEAD`, not your working
directory or the index — so `git status` looking clean doesn't mean `verify`
will pass, and a dirty working tree doesn't hide a real problem either.

If `verify` itself fails to run (rather than reporting plaintext), see "key
unavailable" below — it fails closed rather than silently skipping the
check when it can't authenticate a file.

## "key not found" / exit code 2

```
$ git secret unlock
Error: keybackend: key not found: .repo-enc/key
```

**Cause:** the `file`-backend key isn't present at `key_source` (it's
gitignored by design — never committed, so a fresh clone has no key until
you copy it in out-of-band), or the `env`-backend variable isn't set, or (for
`gpg`) no local secret key can open `.repo-enc/key.gpg`.

**Fix, by backend:**

- `file`: copy the key file from wherever it was shared out-of-band into
  `.repo-enc/key` (path from `.repo-enc.yml`'s `key_source`).
- `env`: `export <VAR>=<hex-value>` (the value `init`/`rotate-keys` printed
  when the key was generated).
- `gpg`: confirm your GPG secret key is in your keyring
  (`gpg --list-secret-keys`) and is one of the fingerprints in
  `.repo-enc.yml`'s `gpg_recipients`. If it isn't, ask an existing recipient
  to run `git secret adduser <your-fingerprint>`.

## "not a full GPG fingerprint" during `init`/`adduser`/`git-secret-seal`

```
$ git secret init --key-backend gpg --gpg-recipient shortid123
Error: init: load config: config: gpg_recipients entry "shortid123" is not
a full GPG fingerprint (40 or 64 hex characters) — short IDs and emails
are ambiguous and not accepted
```

**Cause:** a short key ID or email was passed instead of a full fingerprint.
This is enforced deliberately (short IDs are spoofable/collision-prone) and
applies identically to `.repo-enc.yml`'s `gpg_recipients` and
`git-secret-seal --recipient`.

**Fix:** get the full fingerprint and use that instead:

```bash
gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}'
# or, for someone else's public key already in your keyring:
gpg --list-keys --with-colons <email-or-shortid> | awk -F: '/^fpr/{print $10; exit}'
```

## GPG private key import errors in a container/CI environment

```
{"msg":"read GPG private key file","path":"/nonexistent.asc",
 "error":"open /nonexistent.asc: no such file or directory"}
```

**Cause (most common):** `--gpg-private-key-file`/`GPG_PRIVATE_KEY_FILE`
points at a path that doesn't exist in the container — usually a Secret
volume mount path mismatch, or the Secret key inside it doesn't match
`existingSecretKey` in the Helm chart's `gpgPrivateKey` values.

**Fix:** confirm the mount:

```bash
kubectl exec -it <controller-pod> -- ls -la /path/to/mounted/secret
```

and that the chart's `gpgPrivateKey.existingSecretKey` (default
`private.asc`) matches the actual key name in your `Secret`
(`kubectl get secret <name> -o jsonpath='{.data}' | jq keys` — you're
checking key *names*, not decoding the values).

**A second common cause in CI (not container-startup):** `gpg
--encrypt`/`--decrypt` needing `gpg-agent`/`pinentry` in a non-interactive
session. The controller avoids this — it imports the key into its own
isolated `GNUPGHOME` at startup and never needs an interactive agent — but
if you're running `git secret`/`gpg` directly in CI:

- keep a passphrase-less secret key in a CI-local ephemeral `GNUPGHOME`
  (`gpg --batch --passphrase '' --quick-generate-key ...`, same as the
  [quickstart](../getting-started/quickstart.md) does for the controller
  identity), or
- prefer the `file`/`env` key backends for CI and reserve `gpg` for
  interactive developer machines (see the main README's "Key backends"
  section for the tradeoffs).

## Unencrypted-secret detection warnings from `kubectl-secret`

`kubectl secret apply`/`view` only decrypts values that already start with
`repo-enc:v1:` — anything else passes through unchanged. If a value you
expected to be decrypted isn't, check:

- it's actually listed under `k8s_secret_paths` in `.repo-enc.yml` (exact
  repo-relative path, not a glob);
- the manifest's `apiVersion`/`kind`/`metadata.name`/`metadata.namespace`
  match what it was sealed for — `encrypt-value` binds ciphertext to the
  object identity, so copying a `repo-enc:v1:...` blob into a differently-
  named/namespaced manifest fails to decrypt rather than silently
  succeeding on the wrong object;
- it isn't intentionally listed in `k8s_plaintext_keys` for that manifest
  (that's a deliberate allow-list for non-secret values living alongside
  real ones, not a bug).

## `GitSecret` stuck with a `TargetConflict` condition

**Cause:** a `Secret` with the same name already exists in that namespace
and isn't owned by this `GitSecret` — the controller refuses to clobber it.

**Fix:** either rename the `GitSecret`/target, delete the pre-existing
`Secret` if it's safe to, or set `spec.target.adopt: true` to deliberately
take ownership of it.

## Where to look next

- [Quickstart](../getting-started/quickstart.md) — a known-good end-to-end
  flow to compare against.
- [Threat model](../security/threat-model.md) — what the security
  invariants actually are, if a failure looks like it might be one of them
  failing rather than a config mistake.
- Still stuck, or think you've found a security-relevant bug rather than a
  config issue? See [SECURITY.md](../../SECURITY.md) for the disclosure
  process; everything else, open a GitHub issue.
