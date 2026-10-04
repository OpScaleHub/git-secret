# End-to-end product audit — September 2026

Baseline: `main` @ `d8a8746` (post-v0.10.0). Date: 2026-09-29.

Scope: everything a user or operator touches — landing page, README, every doc
under `docs/`, chart READMEs, CLI help text, the Helm chart, the controller,
webhook, sealing UI and the CLI — reviewed statically **and** exercised live on
a local `kind` cluster (Kubernetes v1.34) with the image built from HEAD.

This is an audit, not a change set. The proposed backlog is at the end.

## Maintainer decisions (2026-09-29)

| Question | Decision |
|---|---|
| B4 chart naming | **Fix** the doubled names. Handled as part of the rename (the chart becomes `keyfold`). |
| L1 `git-secret-server` | **Remove.** Its last consumer already runs on the CRD. |
| M7 competitor framing | **Remove every sealed-secrets / kubeseal reference** in docs, code and help — done in PR #103. |
| M9 name collision | **Rename.** Proposal: [ADR-0001 — Keyfold](../adr/0001-product-name.md). |

Deployments of this project elsewhere are separate projects and are not
tracked here; compatibility notes go in `UPGRADING.md` for any user.

---

## 1. Verdict

**The engine is sound; the product around it is not yet coherent.**

- The core cryptographic claims hold up live: multi-recipient sealing, one
  object consumed by two controller identities, recovery-key rewrap to a
  replacement cluster with `encryptedData` byte-identical, AEAD object
  binding, last-recovery-key guard, admission enforcement, no-clobber adoption,
  owned-Secret self-healing. All 16 Go packages pass with `-race` and
  `REQUIRE_GPG_TESTS=1`.
- But the audit found **5 real defects in code/chart** (one of them in the
  admission webhook's security boundary), **3 functional gaps that undercut the
  headline recovery claim**, and a **messaging/positioning problem** severe
  enough that the landing page describes a different product from the README.

## 2. What was exercised live

Two controller identities (`ctrl-a`, `ctrl-b`), a human operator (`alice`), an
offline recovery key, and a replacement controller (`ctrl-a2`), each in its own
isolated `GNUPGHOME`. Chart installed with webhook, pubkey Service, pubkey
ConfigMap Job and sealing UI enabled, release namespace labelled Pod Security
`restricted`.

| # | Scenario | Result |
|---|---|---|
| 1 | `helm install` into a PSS-`restricted` namespace | ❌ **fails** — see B2 |
| 2 | Same, with `podSecurityContext.seccompProfile=RuntimeDefault` | ✅ |
| 3 | Controller pubkey via ConfigMap Job and `GET /pubkey` | ✅ fingerprint matches |
| 4 | Seal with `--keyring` (2 controllers + recovery + human) | ✅ (provenance stamped `-dirty`, B6) |
| 5 | Apply → webhook admits → controller decrypts | ✅ `Ready=True`, value correct |
| 6 | Same object, controller identity swapped to `ctrl-b` ("cluster B") | ✅ decrypts |
| 7 | Delete owned Secret | ✅ recreated |
| 8 | Replacement controller `ctrl-a2`, not yet a recipient | ✅ `UnsealFailed`, last Secret retained |
| 9 | New cluster's **public** key alone tries to rewrap | ✅ refused (raw gpg error, B9) |
| 10 | Offline recovery key rewraps to add `ctrl-a2` | ⚠️ works only once the recovery keyring holds **every** remaining recipient's public key (G4); then ✅ `encryptedData` byte-identical, new controller decrypts |
| 11 | `recipients remove` lost controller | ✅ |
| 12 | Remove last recovery recipient | ✅ refused without `--force` |
| 13 | Webhook: `spec.recipients` count tampered | ✅ denied |
| 14 | Webhook: Namespace `required-recipients` missing | ✅ denied |
| 15 | Copy object under a new name | ✅ AEAD fails, no Secret |
| 16 | Re-apply an older manifest not wrapped to this controller | ❌ **denied for the wrong reason** — see B1 |
| 17 | 20 admission calls + 6 pubkey fetches with seal-UI pod in the Service selectors | ✅ no misroutes (masked by named ports, B5) |
| 18 | In-cluster sealing UI, default config | ❌ **every seal fails** — see B3 |
| 19 | RBAC as ServiceAccount | ✅ no `secrets:delete`, no `gitsecrets:update`, VWC scoped |
| 20 | Metrics endpoint | ⚠️ plain HTTP, unauthenticated (B8) |
| 21 | CLI `init --key-backend gpg` → commit → `verify` | ✅ ciphertext at HEAD, plaintext in tree |

A second real `kind` cluster was created for true multi-cluster testing but its
kube-proxy hit the host's inotify limit (`too many open files`, needs a host
`sysctl`); scenario 6 substitutes an identity swap, which exercises the same
cryptographic claim.

---

## 3. Defects (code / chart) — verified

### B1 — Admission webhook unwraps the content key, and rejects objects it cannot unwrap · **High**

`gpgutil.CountRecipients` runs `gpg --batch --list-packets`. Its doc comment
says "--list-packets does not decrypt, so no secret key or agent is required",
and `admission-webhook.md` says the webhook "does not decrypt". Both are false:

- When the controller **is** a recipient, `--list-packets` performs the
  private-key operation and unwraps the content key (output reaches
  `:literal data packet:`) — on every admission request.
- When it **is not**, gpg exits 2 (`No secret key`) and the webhook **denies**
  the object with a raw gpg error, even though the packet count was readable.
  Any object not (yet) wrapped to this cluster — a DR re-apply, a multi-cluster
  object, an old revision — is rejected at admission instead of being admitted
  and reported as `UnsealFailed`.

Fix: `gpg --batch --list-only --list-packets` — verified to count all
recipients, exit 0 and decrypt nothing, whether or not the key is a recipient.
Regression test must use a keyring that is **not** a recipient (the current
tests only use one that is, which is why this was never caught).

### B2 — Chart cannot install under Pod Security `restricted` · **High**

No pod sets `seccompProfile`. Controller, seal-UI and the `publishPublicKey`
hook Job are all rejected; the install hangs on the post-install hook and
fails. PSS `restricted` is the CNCF baseline expectation for a security
controller. Workaround exists via values; the default must change
(`seccompProfile: {type: RuntimeDefault}` in `podSecurityContext`).

### B3 — In-cluster sealing UI broken without a keyring ConfigMap · **Medium**

With `sealUi.enabled=true` and no `keyringConfigMap` (documented as optional),
every seal fails: `can't create directory '/home/git-secret-controller/.gnupg':
Read-only file system`. The #68 fix only creates an isolated `GNUPGHOME` when
the keyring carries public keys. Without a keyring the in-cluster UI has no
public keys at all, so it can never work — the chart should require
`keyringConfigMap` (fail at template time) and the binary should always use an
isolated `GNUPGHOME`.

### B4 — Chart resource names are doubled; documented names are wrong · **Medium**

The `fullname` helper lacks Helm's standard "release name already contains the
chart name" rule. With the release name every doc uses
(`git-secret-controller`), resources are `git-secret-controller-git-secret-controller-*`.
`sealing-console.md` (`svc/git-secret-controller-seal-ui`) and `keyring.md`
(`git-secret-controller-pubkey.<ns>.svc`) give names that do not exist.
**Decision:** fix it, as part of the rename (ADR-0001), with an `UPGRADING.md` note.

### B5 — Selector overlap between controller and seal-UI · **Low–Medium**

The controller Deployment selector and the webhook/pubkey/metrics Service
selectors (`instance`+`name`) also match the seal-UI pod. Traffic is currently
saved only because those Services use named `targetPort`s the seal-UI pod
doesn't declare (its EndpointSlices have `ports: null`). But overlapping
Deployment selectors are unsupported in Kubernetes, `kubectl logs deploy/…`
already lands on the wrong pod, and the chart's own `NOTES.txt`
`port-forward deploy/…` can too. Add an `app.kubernetes.io/component:
controller` label to the controller selector (selector change ⇒ also
compat-sensitive; bundle with B4).

### B6 — Provenance is almost always `-dirty` · Low

`git-secret-seal … > gitsecret.yaml` inside the repo creates the untracked
output file before the dirty check runs, so the natural workflow stamps
`<sha>-dirty`. Ignore untracked files (or only the output path) in the check.

### B7 — `git secret verify` passes on a repo with no commits · Low

Prints `OK - all matched files are encrypted at HEAD.` when `HEAD` does not
exist. Should say "nothing committed yet" (and exit non-zero or distinctly).

### B8 — Metrics served as unauthenticated plain HTTP on port "8443" · Low

`secure: false` on a port conventionally meaning TLS. Contents are not
sensitive, but controller-runtime's secure serving with the authn/authz filter
is the ecosystem default for operators.

### B9 — Rewrap errors are raw gpg · Low (UX, but it is the DR path)

A non-recipient running `recipients add` gets `gpg: decryption failed: No
secret key`; a recovery holder missing a public key gets `skipped: No public
key`. These should say what they mean: *"you are not a current recipient of
this object — one of <fingerprints> must perform the rewrap"* and *"public key
for <fpr> (role recovery) is not in your keyring"*.

### B10 — Minor / cosmetic

- Controller reports Ready while it cannot reach the apiserver (seen on the
  broken second cluster).
- Sealed manifests carry empty `status: {}` / `target: {}`; `TARGET` column is
  empty when the target defaults to the object name.
- CRD install warns `unrecognized format "int64"`.
- Toolchain drift: `go.mod`/CI Go 1.26, images `golang:1.27`, quickstart says
  "Go 1.25+".

---

## 4. Functional gaps that undercut the product claims

### G1 — No way to read a GitSecret outside a cluster · **High (claim vs reality)**

`sealer.Unseal` is called only by the controller. There is no
`git-secret-seal unseal`/`view`. So design goal 8 ("Recovery is possible
entirely outside the cluster") and the DR headline ("the repo + any one key
recovers every secret") are true only in the sense of *re-wrapping to a new
controller* — an operator holding the recovery key cannot actually read the
database password without standing up a cluster. `disaster-recovery.md` §D even
refers to "one `git-secret-seal` unseal", a command that does not exist.

Needed: `git-secret-seal unseal -f FILE [--key K]` → stdout only (invariant #8:
never to disk), refusing when stdout is a TTY unless `--show`.

### G2 — No content-key rotation, no single-value update · **Medium**

The CRD path has no equivalent of the CLI's `rotate-keys`. Consequences:

- Changing **one** value in a `GitSecret` requires re-entering **all**
  plaintext values.
- The documented response to a departing operator who must lose access to
  current values (`disaster-recovery.md` §D → §E) requires the plaintext of
  every value.

Needed: `git-secret-seal rekey -f FILE` (unwrap → fresh content key → re-seal
every value → wrap to the current set) and `git-secret-seal set KEY -f FILE`
(merge one value). This is exactly the "content-key rotation vs. secret-value
rotation" distinction the docs should also teach (see M4).

### G3 — Recipient operations are one file at a time · **Medium**

The "add a cluster" / "decommission a cluster" runbooks say "for every
object". There is no directory/glob mode, so onboarding a cluster across a real
repo is a hand-written shell loop.

Needed: `recipients add|remove|list` over `-f DIR` / multiple `-f` / a glob,
with a dry-run summary and all-or-nothing writes.

### G4 — Rewrap requires every remaining recipient's public key locally · **Medium**

Found live: the recovery holder (an offline key by design) could not add the
new controller until it had imported the public keys of **all** remaining
recipients. No doc says so, and `recipients add/remove` cannot take a
`--keyring` that carries embedded `publicKey`s (only the UI imports them).

Needed: `--keyring` on `recipients`/`--rewrap` with public-key import into an
isolated `GNUPGHOME`, and the DR runbook's prerequisites listing "the current
recipient public keys" explicitly.

### G5 — Keyring `publicKey` not bound to its fingerprint · Low

`importKeyringPubKeys` imports whatever armored block an entry carries without
checking it matches that entry's fingerprint. `keyring.md`'s trust note ("an
injected fingerprint you don't have fails the seal") is false once the keyring
carries its own public keys (the UI path, a `ConfigMap`, or a URL). Verify the
imported key's fingerprint; update the trust note: *whoever can edit the
keyring decides who can decrypt.*

### G6 — Two unrelated recipient registries · Low (clarity)

The CLI's repo key is wrapped to `.repo-enc.yml` `gpg_recipients`; GitSecrets
are wrapped to `keyring.yaml`. Nothing explains they are independent key
hierarchies, and a team using both maintains two lists.

### G7 — No executable Kubernetes example, no e2e in CI · Medium

`examples/` has only the CLI demo. Controller tests use the fake client; the
landing page's "verified end-to-end against a real cluster" was a manual run.
The scenario table in §2 should become `test/e2e` on `kind` in CI — it would
have caught B1, B2 and B3.

---

## 5. Messaging, positioning and documentation

### M1 — The landing page describes a different product · **High**

README tagline: *"A recoverable, Git-native cryptographic control plane for
Kubernetes secrets."* Landing page `<title>` and hero: *"Plaintext on disk.
Ciphertext in history."* — the first **five** sections (hero, six feature
cards, how-it-works, quick start, commands, `.repo-enc.yml`) are about the git
hooks. Kubernetes appears as *"On Kubernetes?"* and starts at section six. The
recovery/multi-recipient story — the actual differentiator — is one paragraph.

### M2 — The quickstart teaches the anti-pattern · **High**

`docs/getting-started/quickstart.md` seals to the controller key **only** —
exactly the single-key setup invariant #1 forbids and the whole design
exists to avoid. It also runs the controller as a local process while the
landing page installs with Helm (two different "first five minutes"), and ends
with an unprompted *"there is no ArgoCD Config Management Plugin integration in
this project today"*.

### M3 — Contradictions between surfaces · Medium

| Claim | Where | Contradicted by |
|---|---|---|
| "GPG is entirely optional" | landing hero | README: `gpg` recommended, required for Kubernetes/CI |
| Quick start uses the `file` backend | landing | README recommends `gpg` |
| "prefer `file`/`env` for CI" | README + landing | README: `gpg` is "the only backend that works with automated consumers" |
| "The CRD is the source of truth" (OWNED card) | landing | README design goal 6: Git is the source, the controller a consumer |
| kubectl-secret "no release binary yet" (×2) | landing | 10 `kubectl-secret-*` assets on every release since v0.8.0 |
| `verify` "is ciphertext" | landing | README: "authentically encrypted" |
| "they need the key transferred out-of-band" | README/landing quick start | only true for the `file` backend |

### M4 — Terminology is not controlled · Medium

- **decrypt / unwrap / rewrap**: landing says rewrap "re-encrypts only that
  wrapped key" and "a newly-added recipient decrypts independently, with no
  involvement from the key that did the rewrapping" — accurate after the fact,
  but it hides the one rule users must know: **only an existing recipient can
  add a new one; a new cluster's public key cannot rewrap anything.** No
  top-level surface says this.
- **content key / CEK / content-encryption key / repo key / "the key"** used
  interchangeably.
- **Same verb, different semantics**: CLI `removeuser` = revocation (full
  rotation); CRD `recipients remove` = rewrap, *not* revocation. The docs
  explain this, carefully — but the naming invites the mistake.
- **"rotate"** means content-key rotation in the CLI (`rotate-keys`) and
  secret-value rotation in the DR runbook; the CRD path has no content-key
  rotation at all (G2).

Proposed glossary (one page, linked everywhere): *payload encryption (AEAD
envelope)*, *content key*, *recipient / identity*, *wrap / unwrap*,
*rewrap* (change who can unwrap; no value touched), *rekey* (new content key,
values re-encrypted, plaintext unchanged), *secret rotation* (new plaintext at
the source), *revocation* (= rekey or secret rotation, never rewrap alone).

### M5 — Stale status and dangling references · Medium

- `threat-model.md`: "Status: initial draft (#38)"; #47 "proposed" (shipped);
  #56/#57 listed as both open and closed; invariant #9 and T11 point to closed
  #40 for per-fingerprint verification that was never built.
- `disaster-recovery.md` §F: provenance "future work" (shipped, `provenance.md`).
- `design-rationale.md`: sealing console "see the backlog" (shipped).
- `recipient-lifecycle.md`: "multi-cluster" link points to `overview.md`.
- `admission-webhook.md`: a dated v0.8.0 test log inside an architecture doc.
- 17 `#NN` issue references across user-facing docs; `docs/README.md` doesn't
  list the quickstart, troubleshooting or UPGRADING.

### M6 — Legacy and CD-specific framing · Medium

- Argo CD named as *the* apply path in runbooks ("point the new cluster's
  ArgoCD at the repo", "ArgoCD pointed at the same repo does this for you"),
  landing install comment, and `<meta keywords>`.
- Echoes of the old CMP integration: quickstart's CMP disclaimer; kubectl-secret
  section "no sidecar, no manifest-generation hook to wire up by hand".
- `design-rationale.md` carries internal context that doesn't belong in public
  product docs (Iran-hosted target / geo-blocking precedent, "the 25 closed
  findings in #1–#25").

Rule going forward: GitOps described generically — "whatever applies your
manifests (Argo CD, Flux, `kubectl apply`)" — never a single tool as the
architecture.

### M7 — Competitor framing is inconsistent · Low–Medium

Landing page was cleaned (#88), but README still has "Modeled on Bitnami
`sealed-secrets`' shape" and a Bitnami/SOPS/Vault comparison table,
`design-rationale.md` frames the CRD around sealed-secrets, and
`git-secret-seal --help` says it "avoids sealed-secrets' single-keypair DR
weakness" and is "the kubeseal equivalent". Pick one policy (a neutral
comparison page, or none) and apply it everywhere.

### M8 — Information architecture · Medium

README is 452 lines; the Kubernetes section starts at line 300 — the first
two-thirds are CLI and kubectl-plugin detail (`skip-worktree`, pull-conflict
recovery). There is no single "Concepts"
page explaining the envelope → recipients → rewrap → rotation model; it is
spread over six documents. Recommended IA:

```
README (≤150 lines): definition · why · 60-second picture · install · links
docs/
  concepts.md        envelope, recipients, rewrap vs rekey vs rotation, glossary
  getting-started/   kubernetes.md (Helm, multi-recipient from line 1) · cli.md
  guides/            add-a-cluster · replace-a-cluster · offboard-a-person ·
                     recover-without-a-cluster · troubleshooting
  reference/         git-secret-seal · git-secret · kubectl-secret · CRD · chart values
  security/          threat-model · disaster-recovery · supply chain
  adr/               (reinstated — see L2)
```

### M9 — Name collision · decision needed

"git-secret" is also the name of a long-established, unrelated tool
(sobolevn/git-secret, git-secret.io) that does GPG file encryption in Git —
the same search space. That hurts discoverability and invites confusion with
the CLI half of this project. Plus three internal legacy names persist in
formats (`.repo-enc.yml`, `repo-enc:v1:`, `SECRETIZE_SKIP_HOOKS`,
`REPO_ENC_CONFIG_DIR`). **Decision: rename** — see [ADR-0001](../adr/0001-product-name.md) (Keyfold).

---

## 6. Legacy cleanup

### L1 — `git-secret-server` · decision needed

Untouched since v0.6, yet every release still builds, signs and publishes it:
4 binaries, a container image, a Helm chart, CI lint, and it is listed on the
landing page's download list. **Decision: remove.** Delete `cmd/git-secret-server`, `internal/decryptserver`,
`charts/git-secret-server`, their release jobs, CI lint and every doc mention;
note it in CHANGELOG/UPGRADING. Last published artifacts stay available.

### L2 — ADRs

`docs/adr/` was deleted in favour of `design-rationale.md`. For a project
positioning toward CNCF norms, reinstate short ADRs (retro-written, dated)
for the decisions that are genuinely settled: CRD over CMP/ESO; multi-recipient
GPG wrapping; rewrap ≠ revocation; no decrypt endpoint; self-signed webhook
certs (single replica); server-side sealing console. `design-rationale.md`
then becomes a short history page linking to them.

---

## 7. Proposed backlog (replaces the draft 8-issue epic)

Every issue carries the agent contract: inspect HEAD first; report
discrepancies before assuming; preserve compatibility unless authorised;
focused PR; regression test per behaviour change; docs + generated artifacts
in the same PR; don't redo #77/#78/#79.

| # | Issue | Covers | Size | Compat |
|---|---|---|---|---|
| 1 | Webhook `CountRecipients` must not decrypt (`--list-only`) + non-recipient regression test + doc fix | B1 | S | safe |
| 2 | Chart: PSS-restricted by default, controller component label, seal-UI requires keyring + isolated GNUPGHOME, secure metrics | B2 B3 B5 B8 | M | selector change ⇒ upgrade note |
| 3 | Remove `git-secret-server` (code, chart, release jobs, docs) | L1 | M | breaking (announced) |
| 4 | Rename to Keyfold per ADR-0001, incl. chart fullname fix and `keyfold migrate` | M9 B4 | L | breaking, migration tool |
| 5 | `unseal` (offline read, stdout only) | G1 | M | additive |
| 6 | `rekey` + `set KEY` (single-value update) | G2 | M | additive |
| 7 | Bulk recipient ops (dir/glob) + `--keyring` with pubkeys on rewrap + key/fingerprint binding + human errors | G3 G4 G5 B9 | M | additive |
| 8 | Small CLI fixes: provenance `-dirty`, `verify` with no HEAD, empty `status`/`target` in output | B6 B7 B10 | S | safe |
| 9 | Concepts + glossary page; terminology sweep across help, docs, landing | M4 G6 | M | docs |
| 10 | README restructure, docs IA, stale-ref sweep, generic GitOps wording, ADRs reinstated | M3 M5 M6 M8 L2 | L | docs |
| 11 | Landing page rewrite — Kubernetes-first, recovery-first; CLI secondary | M1 M2 | L | docs |
| 12 | `kind` e2e in CI codifying §2; runnable `examples/kubernetes/` | G7 | M | CI |
| 13 | Final consistency audit + release | all | S | — |

Order: 1 → 2 → 3 → 4 (rename) → 5/6/7/8 (parallel, built under the new name) →
9 → 10 → 11 → 12 → 13. The rename lands before new commands and docs so
nothing is written twice; docs (9–11) come after the commands so they describe
commands that exist. M7 is already done (PR #103).

Open Dependabot PRs #99–#102 (actions group, controller-runtime 0.25.1 patch,
debian + golang base-image digests) are routine and can land before item 1.

### Proposed product definition (for 9–11)

> **Keyfold — recoverable, multi-recipient secrets for Kubernetes, stored
> encrypted in Git.** Seal once to every cluster and a recovery key; a
> controller turns it into a `Secret`. Add a cluster without re-encrypting a
> single value. Lose a cluster, a controller or a key — recover from the repo
> and any one authorised key. No vault, no external store, no network hop.

Ranked selling points: (1) recoverable by design; (2) add/replace clusters by
rewrap, no re-encryption; (3) Kubernetes-native CRD + controller, nothing
external to run; (4) reviewable — recipients and provenance visible in the
diff; (5) also a standalone Git CLI for files, no Kubernetes required.

---

## 8. Status after epic #117 (2026-10-04)

Every finding was worked through epic #117; the final consistency pass
(this addendum) found only two small reference gaps, fixed alongside it.

| Finding | Resolution |
|---|---|
| B1 webhook decrypts / denies non-recipient objects | #105 → PR #118 (`gpg --list-only`) |
| B2 Pod Security `restricted` · B3 seal-UI · B5 selectors · B8 metrics | #106 → PR #119 |
| B4 doubled chart names | PR #119 (pulled forward from the rename) |
| B6 provenance `-dirty` · B7 `verify` w/o HEAD · B10 cosmetics, readiness, toolchain | #112 → PR #127 (int64 CRD warning: upstream, documented) |
| B9 raw gpg errors | PRs #125, #127 |
| G1 offline unseal | #109 → PR #123 |
| G2 rekey / single-value update | #110 → PR #124 |
| G3 bulk recipients · G4 keyring public keys · G5 key/fingerprint binding | #111 → PR #125 |
| G6 two key hierarchies unexplained | #113 → PR #128 (`docs/concepts.md`) |
| G7 no e2e / example | #116 → PR #134 (16 checks on kind, in CI) |
| M1 landing page · M3 (landing part) | #115 → PR #131 — **held until the release is tagged** |
| M2 quickstart anti-pattern · M3 · M5 · M6 · M8 · L2 ADRs | #114 → PR #130 |
| M4 terminology | PRs #128, #130 and this pass |
| M7 competitor references | PR #103 |
| M9 name collision | ADR-0001 → #108 → PR #122; repository renamed (PR #132), site on keyfold.opscale.ir (PR #133) |
| L1 `git-secret-server` | #107 → PR #121 |

**Final pass checks** (source ↔ CRD ↔ chart ↔ CLI ↔ README ↔ docs ↔ landing):
CLI help vs. reference docs (every command and flag); every chart value
documented; release artifact names vs. documented names; CRD and deepcopy
regenerated with no diff; terminology sweep (remaining Argo CD mentions are the
`kubectl keyfold` warning feature and generic "Argo CD, Flux, …" examples;
`SECRETIZE_SKIP_HOOKS` is the honoured legacy name); all relative links and
anchors in every Markdown file and all 18 repository links on the new landing
page resolve; both examples execute.

**Found along the way, open:** #126 intermittent local gpg test failure (never
on CI); #129 the repository has no `LICENSE` file — maintainer decision.
