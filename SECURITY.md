# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via [GitHub's private vulnerability
reporting](https://github.com/OpScaleHub/git-secret/security/advisories/new)
("Report a vulnerability" on the repository's Security tab).

Please do **not** open a public issue for a suspected vulnerability.

Include, as far as you can:

- affected component — CLI / Git hooks, the `GitSecret` CRD + controller, or the
  legacy `git-secret-server`;
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

The latest tagged release. `git-secret-server` receives security fixes only; the
`GitSecret` CRD + controller is the actively developed integration.

## Disclosure

We aim to acknowledge a report within a few working days and to agree a
coordinated disclosure timeline from there. Reporters are credited in the advisory
unless they ask not to be.
