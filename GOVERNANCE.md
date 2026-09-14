# Governance

`git-secret` is currently maintainer-led: a small set of maintainers with
commit access make day-to-day decisions by consensus, and this document
describes that as it actually operates today rather than aspiring to a
committee structure the project doesn't yet have the contributor base to
support.

## Roles

- **Maintainers** — have commit access, review and merge PRs, cut releases,
  and triage security reports (see [SECURITY.md](SECURITY.md)). See the
  repository's collaborator list on GitHub for the current maintainers.
- **Contributors** — anyone who opens an issue or PR. No formal membership
  step is required to contribute; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Decision-making

- Routine changes (bug fixes, docs, dependency bumps, most features) are
  decided by normal PR review: one maintainer approval is sufficient to
  merge, absent an objection from another maintainer.
- Changes to the security model, the `GitSecret` CRD's API surface, or the
  crypto core (`crypto/`, `internal/gpgutil`, `internal/sealer`) require
  explicit sign-off from a maintainer with security context on the change,
  and should reference the relevant section of the [threat
  model](docs/security/threat-model.md).
- API compatibility for the `GitSecret` CRD follows the additive-only policy
  in [UPGRADING.md](UPGRADING.md); a maintainer proposing a breaking change
  must get agreement from all active maintainers first.
- Disagreements that can't be resolved in PR review are discussed in a
  GitHub issue and decided by simple majority of active maintainers. In
  practice, with the current maintainer count, this hasn't been needed yet —
  this section exists so the process is defined before it's needed under
  pressure.

## Becoming a maintainer

Sustained, high-quality contribution (code, review, or triage) over time is
the path — there's no fixed tenure requirement. An existing maintainer
proposes new maintainers; other maintainers have a chance to object before
the change takes effect.

## Project lifecycle

This project is pre-1.0 for the CRD/controller surface specifically (see
[UPGRADING.md](UPGRADING.md) for what "1.0" will mean for API stability); the
CLI/git-hooks surface is stable and has been used in production. There is no
committed roadmap beyond the issue tracker — the backlog reflects actual
demonstrated need rather than speculative feature work (see
[CONTRIBUTING.md](CONTRIBUTING.md) for how proposals get scoped).

## Code of conduct

Governed by the [CNCF Code of Conduct v2.0](CODE_OF_CONDUCT.md). Reports go
through the process described there.
