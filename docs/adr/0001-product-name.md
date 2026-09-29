# ADR-0001 — Rename the product to Keyfold

- Status: **Proposed**
- Date: 2026-09-29
- Context: [September 2026 e2e audit](../audit/2026-09-e2e-product-audit.md), finding M9

## Context

"git-secret" collides with an established, unrelated project in exactly the
same space: [sobolevn/git-secret](https://github.com/sobolevn/git-secret)
(≈4,000★, git-secret.io) — "a bash-tool to store your private data inside a git
repository" using GPG. Anyone searching for this project finds that one first,
and the CLI half of this project (a GPG-capable git plugin) is easy to confuse
with it.

The project has also outgrown the name. It is no longer "secrets in git" — it
is a recoverable, multi-recipient secret system for Kubernetes whose defining
property is that the content key is wrapped to many independent keys, any one
of which can recover it. The current name says nothing about that.

Three older internal names still leak through: `repo-enc` (`.repo-enc.yml`,
`repo-enc:v1:`, `REPO_ENC_CONFIG_DIR`), `secretize` (`SECRETIZE_SKIP_HOOKS`)
and `git-secret` itself.

## Decision

Rename the product to **Keyfold**.

- *Key + fold*: many recipient keys folded around one content key; a fold is
  also the enclosure that keeps a flock safe. It names the mechanism that makes
  the product different.
- Clear namespace: 7 GitHub repositories use the word, none in security or
  Kubernetes, the most-starred has 1★ (checked 2026-09-29).
- Short, pronounceable, works as a CLI verb (`keyfold seal`, `keyfold unseal`).

### Name map

| Surface | Today | After |
|---|---|---|
| Product / site | git-secret · git-secret.opscale.ir | **Keyfold** · keyfold.opscale.ir (old host redirects) |
| GitHub repo / Go module | `OpScaleHub/git-secret` | `OpScaleHub/keyfold` (GitHub redirects the old URL) |
| Sealing CLI (primary tool) | `git-secret-seal` | `keyfold` |
| Git plugin | `git-secret` → `git secret …` | `git-keyfold` → `git keyfold …` |
| kubectl plugin | `kubectl-secret` → `kubectl secret …` | `kubectl-keyfold` → `kubectl keyfold …` |
| Controller binary / image | `git-secret-controller` | `keyfold-controller` |
| Helm chart | `git-secret-controller` | `keyfold` (fullname dedupe fixed, audit B4) |
| CRD API group | `git-secret.opscalehub.io/v1alpha1` | `keyfold.opscalehub.io/v1alpha1` |
| CRD kind | `GitSecret` | **unchanged** — it accurately describes the object |
| Annotations | `git-secret.opscalehub.io/*` | `keyfold.opscalehub.io/*` (old keys read during migration) |
| Hook bypass env | `SECRETIZE_SKIP_HOOKS` | `KEYFOLD_SKIP_HOOKS` (old name still honoured, warns) |
| Config dir env | `REPO_ENC_CONFIG_DIR` | `KEYFOLD_CONFIG_DIR` (old name still honoured) |
| Repo config file | `.repo-enc.yml` | `.keyfold.yml` for new repos; `.repo-enc.yml` read forever; both present = error |

### What does not change — ever

Ciphertext formats are bound data, not branding:

- the `RENC` envelope magic and header,
- the `repo-enc:v1:` per-value prefix,
- the AEAD additional-authenticated-data layouts,
- the wrapped-key format.

Every existing blob, manifest and repo must keep decrypting with no
re-encryption.

## Migrating live objects (API group change)

Changing the group means a new CRD, so each object moves once. No value is
re-encrypted: a `GitSecret`'s AAD is `namespace/name/key` and never includes the
group, so the conversion is a pure text rewrite.

1. `keyfold migrate -f DIR` rewrites manifests in place: `apiVersion`,
   annotation keys, and sets `spec.target.adopt: true` so the new object can
   take over the existing `Secret`.
2. Install the `keyfold` chart alongside the old one (different CRD, different
   Lease name — no conflict).
3. Per object: `kubectl delete gitsecrets.git-secret.opscalehub.io NAME
   --cascade=orphan` (the `Secret` stays, workloads are untouched), then apply
   the migrated manifest. The new controller adopts the `Secret`.
4. When nothing is left on the old group, uninstall the old chart and delete
   the old CRD.

`UPGRADING.md` documents this; a `kind` e2e test covers it.

## Sequencing

1. Bug fixes that would otherwise be done twice (webhook B1, chart B2/B3/B5).
2. Remove `git-secret-server` — don't rename a component that is being deleted.
3. **Rename** (this ADR) — one release, e.g. `v0.11.0`, with the migration
   command and guide.
4. Docs, concepts page and landing-page rewrite — written once, under the new name.

## Consequences

- One breaking release. Pre-1.0 and `v1alpha1`, so allowed, but it needs
  `UPGRADING.md` coverage and the migration tool above.
- Old images, charts and binaries stay published at their last version; no new
  `git-secret-*` artifacts after the rename release.
- Out-of-repo actions: rename the GitHub repo, add DNS for
  `keyfold.opscale.ir` and redirect the old host, and create the new GHCR
  package names.
