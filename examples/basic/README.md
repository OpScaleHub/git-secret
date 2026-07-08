# Basic example: commit → clone → checkout, plus key rotation

`repo-enc.yml.sample` is a sample `.repo-enc.yml` — copy it to your repo root
as `.repo-enc.yml`, or just run `git secret init` which writes an equivalent
default for you.

`demo.sh` runs the whole cycle end-to-end in scratch repos under a temp
directory (nothing touches your real repos or global git config):

```bash
./demo.sh
```

It walks through:

1. `git secret init` in a fresh repo.
2. Writing a plaintext secret and committing it — the `pre-commit` hook
   encrypts what's staged; your working copy stays plaintext.
3. `git secret verify` confirming `HEAD` holds no leaked plaintext.
4. Cloning the repo — the clone's working tree starts out as ciphertext,
   because that's exactly what's committed.
5. Onboarding the clone: install hooks, then copy the (gitignored,
   never-committed) key file over out-of-band, and run the
   `post-checkout` hook to decrypt.
6. `rotate-keys` re-encrypting the secret under a brand new key.

Read `demo.sh` alongside the "How it works" section of the top-level
README — each step in the script is a one-line version of what's
documented there.
