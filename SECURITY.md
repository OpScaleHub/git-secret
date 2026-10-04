# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via [GitHub's private vulnerability
reporting](https://github.com/OpScaleHub/keyfold/security/advisories/new)
("Report a vulnerability" on the repository's Security tab).

Please do **not** open a public issue for a suspected vulnerability.

Include, as far as you can:

- affected component — CLI / Git hooks, `kubectl-keyfold`, `keyfold`, or
  the `GitSecret` CRD + controller (incl. the Helm chart);
- affected version or commit;
- a minimal reproduction;
- the impact you believe it has, mapped to the [threat
  model](docs/security/threat-model.md) if you can.

Do not include working exploit code or a step-by-step extraction path in the
initial report — describe the class of problem; we will follow up for detail.

## Scope

In scope: anything that breaks one of the [security
invariants](docs/security/threat-model.md#4-security-invariants) — for example
plaintext or key material reaching logs / Events / `status`, a `GitSecret`
decrypting outside the object it was sealed for, recipient input bypassing full-
fingerprint validation, or the `pre-push` / `verify` plaintext guard failing open.

Out of scope (documented non-goals): a malicious Kubernetes cluster administrator,
a compromised operator workstation, and historical ciphertext exposure in Git
after a private-key compromise. See the threat model for why.

## Supported versions

The latest tagged release. `git-secret-server` (the former External Secrets
Operator bridge) was removed after v0.10.0 and is no longer supported; its last
published artifacts are v0.10.0.

## Disclosure

We aim to acknowledge a report within a few working days and to agree a
coordinated disclosure timeline from there. Reporters are credited in the advisory
unless they ask not to be.

## Verifying a release

Every tagged release carries cryptographic provenance in addition to the
`.sha256` sidecars (which prove integrity, not authenticity).

**Binaries** — SLSA build provenance, signed with GitHub's OIDC identity:

```
gh attestation verify ./keyfold-linux-amd64 --repo OpScaleHub/keyfold
```

**Container images** — signed with keyless [cosign](https://docs.sigstore.dev/),
plus provenance + SBOM attestations:

```
cosign verify \
  --certificate-identity-regexp '^https://github.com/OpScaleHub/keyfold/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/opscalehub/keyfold-controller:<tag>

cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/OpScaleHub/keyfold/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/opscalehub/keyfold-controller:<tag>
```

Releases up to **v0.10.0** were built before the repository was renamed from
`OpScaleHub/git-secret`; their images are `ghcr.io/opscalehub/git-secret-controller`
and their signatures carry the old identity — verify them with
`--certificate-identity-regexp '^https://github.com/OpScaleHub/git-secret/'`.
`gh attestation verify --repo OpScaleHub/keyfold` works for both.

**SBOM** — an SPDX SBOM of the module graph (`keyfold-sbom.spdx.json`) is
attached to each GitHub release; the images carry their own finer-grained SBOM
attestation (`cosign download sbom ...` / `--type spdxjson`).

All CI/release workflows pin every third-party action to a commit SHA
(`.github/dependabot.yml` keeps the pins current) and run with a default-deny
token (`permissions: {}` at the workflow root, each job re-declaring only what it
needs).
