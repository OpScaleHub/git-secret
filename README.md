# Git Secret Manager (`git-secret`)

`git-secret` is a single-binary Git plugin that transparently encrypts sensitive files in a repository. You keep working with plaintext in your working tree; the installed git hooks make sure only ciphertext ever reaches your commit history.

## Features

- **Transparent encryption**: git hooks (`pre-commit`, `post-checkout`, `post-merge`, `pre-push`) encrypt/decrypt automatically as you commit, checkout, merge, and push — no manual encrypt/decrypt step in the common case.
- **Modern AEAD crypto**: XChaCha20-Poly1305 by default (AES-256-GCM available), no GPG dependency.
- **Config-driven**: glob `patterns` in a committed `.repo-enc.yml` decide which files are in scope; everything else is left untouched.
- **Pluggable key backends**: `file` (a local, gitignored key file) or `env` (an environment variable) today; the `Backend` interface makes adding GPG/KMS backends straightforward.
- **Safety net**: `verify` and the `pre-push` hook refuse to let plaintext that slipped past `pre-commit` (e.g. via `--no-verify`) reach a remote.
- **Cross-platform**: pure Go, no runtime dependencies beyond `git` itself. Installed hooks ship as both POSIX shell and PowerShell scripts.

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
| `unlock` | Decrypt every config-matched file in place — start of session. |
| `encrypt <path...>` | Encrypt specific files in place. |
| `decrypt <path...>` | Decrypt specific files in place. |
| `rotate-keys` | Generate a new key and re-encrypt every config-matched file under it. |
| `verify` | Check every config-matched file committed at `HEAD` is actually ciphertext; exits 3 if not. |
| `hook <name>` | Internal — invoked by the installed hooks, not typically run by hand. |

Exit codes: `0` ok · `1` generic error · `2` key unavailable · `3` `verify` found plaintext in history.

CI note: set `SECRETIZE_SKIP_HOOKS=1` (or run under `CI=1`, already common) to make every installed hook exit 0 immediately without running.

## Configuration (`.repo-enc.yml`)

Committed at the repo root:

```yaml
version: 1
patterns:
  - "secrets/**"
  - "*.secret.env"
exclude:
  - "secrets/public/**"
key_backend: file          # file | env
key_source: .repo-enc/key  # path (file backend) or env var name (env backend)
```

`patterns`/`exclude` are glob paths relative to the repo root; `**` matches any depth. A machine-local `~/.config/repo-enc/config.yml` (or the OS equivalent — set `REPO_ENC_CONFIG_DIR` to override the directory outright, e.g. for containers/CI) can set personal defaults — `key_backend`/`key_source` there apply unless the repo config overrides them, and any `patterns`/`exclude` entries there are unioned with the repo's.

### Key backends

- **`file`** (default): a 32-byte key stored as hex in `key_source` (default `.repo-enc/key`), gitignored automatically by `init`.
- **`env`**: the key is read from the environment variable named by `key_source`. `init`/`rotate-keys` print an `export VAR=<hex>` line when they generate a new one — this backend can't persist anything to disk for you, so copy that value down before the process exits.

## How it works

- **`pre-commit`**: for each staged, pattern-matched file, encrypts the *staged* content and repoints the git index at the ciphertext blob (`git hash-object` + `git update-index --cacheinfo`) — your working-tree file is never touched.
- **`post-checkout` / `post-merge`**: decrypts pattern-matched working-tree files that checkout/merge just populated with ciphertext, if a key is available. Missing key ⇒ warns, doesn't fail the checkout.
- **`pre-push`**: runs the same check as `verify` against `HEAD` and blocks the push if any pattern-matched file was committed as plaintext.
- **`rotate-keys`**: decrypts every matched file under the current key, re-encrypts under a freshly generated one, and only writes anything to disk once every file has round-tripped successfully in memory — a failure partway through never leaves you with an unrecoverable file.

See `examples/basic/` for a runnable walkthrough.

## Publishing & GitHub Pages

The project website is published at: [https://git-secret.opscale.ir](https://git-secret.opscale.ir)

## License

MIT License. See [LICENSE](LICENSE) for details.
