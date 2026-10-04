#!/usr/bin/env bash
# Runnable walkthrough of a commit -> clone -> checkout cycle, plus key
# rotation, using a freshly built Keyfold binary in scratch repos.
# Nothing here touches your real repos or global git config.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

bin="$work/bin/git-keyfold"
mkdir -p "$work/bin"
echo "==> building Keyfold"
(cd "$repo_root" && go build -o "$bin" ./cmd/git-keyfold)
export PATH="$work/bin:$PATH"

repoA="$work/repoA"
mkdir -p "$repoA"
git -C "$repoA" init -q
git -C "$repoA" config user.email demo@example.com
git -C "$repoA" config user.name Demo

echo "==> git keyfold init"
(cd "$repoA" && git-keyfold init "secrets/**")

echo "==> committing .keyfold.yml itself (must be versioned so clones share the same patterns)"
git -C "$repoA" add .keyfold.yml .gitignore
git -C "$repoA" commit -q -m "chore: configure keyfold"

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
(cd "$repoA" && git-keyfold verify)

echo "==> cloning repoA to repoB (simulating a teammate)"
repoB="$work/repoB"
git clone -q "$repoA" "$repoB"
echo "==> repoB's working tree is ciphertext right after clone:"
head -c 60 "$repoB/secrets/db.yaml"; echo

echo "==> onboarding repoB: install hooks (config came from the clone already), then transfer the key out-of-band"
(cd "$repoB" && git-keyfold init)
mkdir -p "$repoB/.keyfold"
cp "$repoA/.keyfold/key" "$repoB/.keyfold/key"

echo "==> simulating the post-checkout hook (what a real checkout triggers)"
(cd "$repoB" && git-keyfold hook post-checkout)
echo "==> repoB's working tree is now plaintext:"
cat "$repoB/secrets/db.yaml"

echo "==> rotate-keys in repoA"
(cd "$repoA" && git-keyfold lock && git-keyfold rotate-keys && git-keyfold unlock)
cat "$repoA/secrets/db.yaml"

echo "==> demo complete: all steps behaved as documented in README.md"
