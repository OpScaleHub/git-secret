# `git keyfold` — encrypted files in a Git repository

The Git plugin half of Keyfold: transparent whole-file encryption driven by git
hooks, with plaintext only in your working tree, never in history. It uses its
own content key per repository — independent of the `GitSecret` objects used on
Kubernetes (see [concepts](../concepts.md#two-places-keyfold-encrypts)). New to
it? Start with [getting-started/git-plugin.md](../getting-started/git-plugin.md).

## Features

- **Transparent encryption**: git hooks (`pre-commit`, `post-checkout`, `post-merge`, `pre-push`) encrypt/decrypt automatically as you commit, checkout, merge, and push — no manual encrypt/decrypt step in the common case.
- **Modern AEAD crypto**: XChaCha20-Poly1305 by default (AES-256-GCM available) does the actual file encryption either way — GPG is never in that path, so `file`/`env` need no GPG dependency at all.
- **Config-driven**: glob `patterns` in a committed `.keyfold.yml` decide which files are in scope; everything else is left untouched.
- **Pluggable key backends**: `gpg` (wraps the key to one or more existing GPG identities — safe to commit, no out-of-band transfer, and the only backend that survives the loss of a single key — **recommended**), `file` (a local, gitignored key file — quick start, local/solo only), or `env` (an environment variable). The `Backend` interface makes adding KMS backends straightforward too.
- **Safety net**: `verify` and the `pre-push` hook refuse to let plaintext that slipped past `pre-commit` (e.g. via `--no-verify`) reach a remote.
- **Cross-platform**: pure Go, no runtime dependencies beyond `git` itself (`gpg` is an optional extra, only needed if you choose that backend). Installed hooks ship as both POSIX shell and PowerShell scripts.

## Install and first steps

See [getting-started/git-plugin.md](../getting-started/git-plugin.md). Building
from source needs Go 1.26+ and `git`; `gpg` is needed for the `gpg` backend.

## Commands

| Command | Effect |
|---|---|
| `init [pattern...]` | Bootstrap: write `.keyfold.yml` (idempotent), generate a key if missing, install hooks. |
| `status` | Show which config-matched files are plaintext vs encrypted in the working tree right now. |
| `lock` | Encrypt every config-matched file in place — end of session. |
| `unlock` | Decrypt every config-matched file in place — start of session. Marks each file `skip-worktree` so `git status` stays quiet while you view them (see below). |
| `encrypt <path...>` | Encrypt specific files in place. |
| `decrypt <path...>` | Decrypt specific files in place. |
| `rotate-keys` | Generate a new key and re-encrypt every config-matched file under it. |
| `verify` | Check every config-matched file and `k8s_secret_paths` manifest committed at `HEAD` is actually, authentically encrypted (and that the raw `file`-backend key isn't committed); exits 3 if not. Requires the key — it fails closed (exit 2) rather than skip the one check that proves anything. |
| `adduser [recipient]` | `gpg` backend only: grant a recipient access — cheap, rewraps the existing key without touching any file. Omit the argument to pick interactively from your local public keyring. |
| `removeuser <recipient>` | `gpg` backend only: revoke a recipient and rotate to a brand new key — a removed recipient already saw the old one, so this re-encrypts every matched file. |
| `hook <name>` | Internal — invoked by the installed hooks, not typically run by hand. |
| `version` | Show version, commit, and Go runtime info. |

Exit codes: `0` ok · `1` generic error · `2` key unavailable · `3` `verify` found plaintext in history.

CI note: set `KEYFOLD_SKIP_HOOKS=1` to make every installed hook exit 0 immediately without running. This is deliberately not tied to the ambient `CI` variable — every CI provider, IDE, and automation wrapper sets `CI=1` by convention, so honoring it implicitly would silently disable both encryption and push-protection in exactly the environments most likely to push on someone's behalf. Opt out explicitly, per invocation.

### `unlock` and `git status`

`unlock` marks each decrypted file `skip-worktree`, so `git status`/`git diff` won't flag it as modified just because you're viewing it locally with plaintext on disk while the index holds ciphertext (that divergence is intentional — see "How it works" below). `lock` clears the flag again.

If you edit an unlocked file and want to commit the change, **run `git keyfold lock` before `git add`** — this isn't just tidiness: recent git versions refuse a plain `git add` on a `skip-worktree`'d path outright (with a confusing sparse-checkout-flavored error, even in repos that never touched sparse-checkout), and `commit -a`/`commit <path>` silently see no change at all, since `skip-worktree` tells git's own diff machinery there's nothing there to look at. `git keyfold lock` sidesteps this entirely — it reads the current working-tree content directly (not through `git add`), re-encrypts it, and clears the flag itself, so the `git add`/`git commit` that follows behaves normally. The supported edit flow is: `unlock` → edit → `lock` → `git add` → `git commit` (as usual — `pre-commit` sees the content is already encrypted and just commits it).

**`git pull`/`git merge` while a file is unlocked.** A clean pull (nobody touched that file upstream) works fine and refreshes the file normally. But if a teammate changes the *same* file you currently have unlocked, `git pull` will refuse with git's standard `Your local changes to the following files would be overwritten by merge` error — `skip-worktree` suppresses `status`/`diff` reporting, but not git's real uncommitted-change protection during a merge, and there's no pre-pull hook available to handle this automatically. If you hit this on a file you were only viewing (not editing), the safe recovery is:

```bash
git keyfold lock                                    # your local view becomes disposable ciphertext
KEYFOLD_SKIP_HOOKS=1 git checkout -- <path>      # discard it back to what's committed
git pull                                            # now safe — post-merge decrypts the new content
```

The `KEYFOLD_SKIP_HOOKS=1` matters: `git checkout -- <path>` fires the `post-checkout` hook even for a single-file restore in current git, which would otherwise immediately re-decrypt what checkout just restored and put you right back in the same diverged, pull-blocking state. If you *were* genuinely editing that file, don't discard it — this is then a real merge conflict like any other and needs manual resolution (commit or stash your change first).

## Configuration (`.keyfold.yml`)

Committed at the repo root. Repositories set up before the Keyfold rename use
`.repo-enc.yml` (keys under `.repo-enc/`) and keep working unchanged — the
format is identical; see [UPGRADING.md](../../UPGRADING.md).

```yaml
version: 1
patterns:
  - "secrets/**"
  - "*.secret.env"
exclude:
  - "secrets/public/**"
key_backend: file          # file | env | gpg
key_source: .keyfold/key  # path (file/gpg backends) or env var name (env backend)
repo_id: 4f3c...           # random, written by `init`; do not edit
gpg_recipients:            # gpg backend only — GPG fingerprints, not secret
  - AAAABBBBCCCCDDDD1111222233334444AAAABBBB
```

`repo_id` is a random per-repo identifier `init` generates and commits. Whole-file
encryption folds it into the authenticated data, so a ciphertext blob sealed here
fails to decrypt if copied into another repository — even one that shares the key.
Repos created before this existed have no `repo_id` and keep working unchanged;
**don't change or remove it** once set, or existing encrypted files stop verifying.

`patterns`/`exclude` are glob paths relative to the repo root (a leading `/` is accepted and normalized away — `/secrets/**` and `secrets/**` are the same pattern); `**` matches any depth. A machine-local `~/.config/keyfold/config.yml` (or the OS equivalent — set `KEYFOLD_CONFIG_DIR` to override the directory outright, e.g. for containers/CI) can set personal defaults — `key_backend`/`key_source` there apply unless the repo config overrides them, and `patterns`/`gpg_recipients`/`k8s_secret_paths` entries there are unioned with the repo's, since those can only *expand* what's protected. `exclude` and `k8s_plaintext_keys` are the opposite — both can only *shrink* protection — so they're taken from the repo config alone; a global config can never silently carve a hole out of a repo's committed policy.

### Key backends

**Use `gpg` for anything beyond a solo local repo** — it is the only backend where every person and CI job gets access through their own key (no raw key handed around), and the only one where losing a single key doesn't threaten recoverability. `init` prints a nudge when it falls back to `file`. (This is the repository's key only: `GitSecret` objects on Kubernetes have their own, independent recipients — see [concepts](../concepts.md#two-places-keyfold-encrypts).)

- **`file`** (default): a 32-byte key stored as hex in `key_source` (default `.keyfold/key`), gitignored automatically by `init`. Giving a teammate or CI job access means copying this raw key to them out-of-band.
- **`env`**: the key is read from the environment variable named by `key_source`. `init`/`rotate-keys` print an `export VAR=<hex>` line when they generate a new one — this backend can't persist anything to disk for you, so copy that value down before the process exits.
- **`gpg`**: the same random 32-byte key, but wrapped (GPG-encrypted) to one or more recipients instead of stored raw. The wrapped blob (default `.keyfold/key.gpg`) is **safe to commit** — unlike the `file` backend's key — since only a matching GPG private key can unwrap it. This solves the onboarding pain point above: a teammate who's already a configured recipient just needs `git keyfold init` (installs hooks; the committed config already has everything else) and their own existing keyring does the rest, no manual key transfer required.

  ```bash
  git keyfold init --key-backend gpg                      # picks interactively from your local GPG keys
  git keyfold init --key-backend gpg --gpg-recipient <fpr> # or specify one directly (repeatable), e.g. for CI

  git keyfold adduser <teammate-fingerprint>   # cheap: rewraps the existing key, no file re-encryption
  git keyfold removeuser <fingerprint>         # forces a full rotate-keys — the removed person already saw the old key
  ```

  Both `adduser`/`removeuser` require `key_backend: gpg` and error otherwise. `status` additionally lists current recipients for this backend.

  **CI and other non-interactive sessions**: there is no pinentry to type a passphrase into. Give the job its own recipient identity — a passphrase-less key in an ephemeral `GNUPGHOME` on the runner, added with `adduser` — rather than sharing a person's key or falling back to the `file`/`env` backends, which mean distributing the raw content key.

## How it works

- **`pre-commit`**: for each staged, pattern-matched file, encrypts the *staged* content and repoints the git index at the ciphertext blob (`git hash-object` + `git update-index --cacheinfo`) — your working-tree file is never touched.
- **`post-checkout` / `post-merge`**: decrypts pattern-matched working-tree files that checkout/merge just populated with ciphertext, if a key is available. Missing key ⇒ warns, doesn't fail the checkout.
- **`pre-push`**: runs the same authenticated check as `verify` against `HEAD`, *and* walks every commit actually being pushed (reading git's ref-update protocol from stdin) that the remote doesn't already have, so a plaintext commit earlier in the range can't reach the remote just because a later commit fixed `HEAD`. The range walk validates envelope structure rather than fully authenticating (a commit deep in history may be sealed under a since-rotated key that the current key can no longer open), which is still enough to catch content that was never encrypted at all.
- **`rotate-keys`**: decrypts every matched file under the current key, re-encrypts under a freshly generated one, and only writes anything to disk once every file has round-tripped successfully in memory — a failure partway through never leaves you with an unrecoverable file.

See [`examples/basic/`](../../examples/basic/) for a runnable walkthrough.

