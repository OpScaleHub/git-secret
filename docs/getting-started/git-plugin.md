# Getting started: encrypted files in a Git repository

`git keyfold` encrypts whole files in a repository with git hooks: you edit
plaintext, Git stores ciphertext. It has its own content key per repository,
independent of the `GitSecret` objects Keyfold uses on Kubernetes — you can use
either without the other ([concepts](../concepts.md#two-places-keyfold-encrypts)).

## 1. Install

Download `git-keyfold-<os>-<arch>` from the
[releases](https://github.com/OpScaleHub/keyfold/releases), check it
(`gh attestation verify ./git-keyfold-linux-amd64 --repo OpScaleHub/keyfold`),
rename it to `git-keyfold` (`git-keyfold.exe` on Windows) and put it on `PATH`.
`git keyfold <command>` then works as a git subcommand. To build instead:
`go build -o git-keyfold ./cmd/git-keyfold` (Go 1.26+).

## 2. Initialise the repository

Use the `gpg` backend, with every person (and CI job) that needs access as its
own recipient:

```bash
cd your-repo
git keyfold init --key-backend gpg \
  --gpg-recipient <your-fingerprint> --gpg-recipient <teammate-fingerprint>
git add .keyfold.yml .keyfold/key.gpg .gitignore
git commit -m "chore: configure keyfold"
```

The repository's content key is wrapped to those fingerprints and committed as
`.keyfold/key.gpg` — safe to commit, nothing to hand around. A teammate who is
a recipient clones, runs `git keyfold init` (installs the hooks; the committed
config does the rest) and their own GPG key decrypts. `init` without
`--gpg-recipient` lets you pick from your keyring. By default it protects
`secrets/**`; pass patterns to change that (`git keyfold init "secrets/**"
"*.secret.env"`).

> The `file` backend (`git keyfold init` with no `--key-backend`) keeps a raw
> key in a gitignored file instead. Fine for a solo experiment; for a team it
> means copying that key to every person and CI job by hand. Prefer `gpg`.

## 3. Use git normally

```bash
echo "password: hunter2" > secrets/db.yaml
git add secrets/db.yaml
git commit -m "add db credentials"    # pre-commit encrypts what is staged
git show HEAD:secrets/db.yaml         # ciphertext in history
cat secrets/db.yaml                   # plaintext in your working tree
```

`pre-push` (and `git keyfold verify`) refuse to let plaintext that slipped past
a bypassed hook reach a remote.

## 4. People and CI

```bash
git keyfold adduser <fingerprint>     # cheap: rewraps the content key, no file re-encrypted
git keyfold removeuser <fingerprint>  # rotates to a new content key, re-encrypts every file
```

For CI, give the job **its own recipient**: a passphrase-less GPG key in an
ephemeral `GNUPGHOME` on the runner, added with `adduser`. Then it decrypts like
any teammate and can be removed on its own.

## Next

- [Command and configuration reference](../reference/git-keyfold.md) — every
  command, `.keyfold.yml`, key backends, how the hooks work, editing unlocked
  files.
- [`kubectl keyfold`](../reference/kubectl-keyfold.md) — encrypt single values
  in a Kubernetes `Secret` manifest instead of whole files.
- [`examples/basic/`](../../examples/basic/) — a runnable end-to-end script.
