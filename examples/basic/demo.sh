#!/usr/bin/env bash
# Runnable walkthrough of a commit -> clone -> checkout cycle, plus key
# rotation, using a freshly built git-secret binary in scratch repos.
# Nothing here touches your real repos or global git config.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

bin="$work/bin/git-secret"
mkdir -p "$work/bin"
echo "==> building git-secret"
(cd "$repo_root" && go build -o "$bin" .)
export PATH="$work/bin:$PATH"

repoA="$work/repoA"
mkdir -p "$repoA"
git -C "$repoA" init -q
git -C "$repoA" config user.email demo@example.com
git -C "$repoA" config user.name Demo

echo "==> git secret init"
(cd "$repoA" && git-secret init "secrets/**")

echo "==> committing .repo-enc.yml itself (must be versioned so clones share the same patterns)"
git -C "$repoA" add .repo-enc.yml .gitignore
git -C "$repoA" commit -q -m "chore: configure repo-enc"

echo "==> writing a secret (plaintext on disk)"
mkdir -p "$repoA/secrets"
echo "password: hunter2" > "$repoA/secrets/db.yaml"
cat "$repoA/secrets/db.yaml"

echo "==> git add + commit (pre-commit hook encrypts what's staged)"
git -C "$repoA" add secrets/db.yaml
git -C "$repoA" commit -q -m "add db credentials"

echo "==> working tree is still plaintext:"
cat "$repoA/secrets/db.yaml"

echo "==> but the commit holds ciphertext:"
git -C "$repoA" show HEAD:secrets/db.yaml | head -c 60; echo

echo "==> verify: confirms HEAD has no leaked plaintext"
(cd "$repoA" && git-secret verify)

echo "==> cloning repoA to repoB (simulating a teammate)"
repoB="$work/repoB"
git clone -q "$repoA" "$repoB"
echo "==> repoB's working tree is ciphertext right after clone:"
head -c 60 "$repoB/secrets/db.yaml"; echo

echo "==> onboarding repoB: install hooks (config came from the clone already), then transfer the key out-of-band"
(cd "$repoB" && git-secret init)
mkdir -p "$repoB/.repo-enc"
cp "$repoA/.repo-enc/key" "$repoB/.repo-enc/key"

echo "==> simulating the post-checkout hook (what a real checkout triggers)"
(cd "$repoB" && git-secret hook post-checkout)
echo "==> repoB's working tree is now plaintext:"
cat "$repoB/secrets/db.yaml"

echo "==> rotate-keys in repoA"
(cd "$repoA" && git-secret lock && git-secret rotate-keys && git-secret unlock)
cat "$repoA/secrets/db.yaml"

echo "==> demo complete: all steps behaved as documented in README.md"
