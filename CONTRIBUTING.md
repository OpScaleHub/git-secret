# Contributing

## Development setup

- Go 1.25 or newer.
- Git (used both to build/test and by the tool itself).
- `gpg` — optional, only needed to run the `gpg`-backend test suites locally.

```bash
git clone https://github.com/OpScaleHub/git-secret.git
cd git-secret
go build ./...
go test ./...
```

The integration tests shell out to real `git`/`gpg` binaries against
temporary repos rather than mocking them, so a working `git` on `PATH` (and
`git config --global user.email`/`user.name` set, same as CI does) is
required to run the suite.

### Running the full test matrix locally

```bash
go build -v ./...
go vet ./...
go test ./... -race -v
```

GPG-dependent tests (`internal/gpgutil` and callers) skip themselves when
`gpg`/`gpg-agent` aren't available, so they run silently green on machines
without GPG installed. CI enforces they actually execute on Linux via
`REQUIRE_GPG_TESTS=1` — if you're adding a new GPG-backed test, make sure it
respects that skip guard rather than failing on GPG-less environments (see
`internal/gpgutil` for the existing pattern).

### Helm chart changes

```bash
helm lint ./charts/git-secret-server
helm lint ./charts/git-secret-controller
```

CI also renders both charts; keep `values.yaml` defaults consistent with the
security posture documented in each chart's README (restricted Pod Security
Standard fields where the workload allows it).

## Pull requests

- Keep PRs focused — one logical change per PR is easier to review and to
  revert if needed.
- Add or update tests for behavior changes; this project treats the test
  suite as the actual specification of CLI/crypto behavior, not just
  regression insurance.
- `go build ./...`, `go vet ./...`, and `go test ./...` must pass. CI runs
  the same on Linux/macOS/Windows plus `govulncheck` and Trivy (advisory) and
  `helm lint` on both charts — a green CI run is the bar.
- Update the relevant doc (`README.md`, `docs/`, chart `README.md`) in the
  same PR as the behavior it describes — this repo does not carry a separate
  "update docs later" pass.
- Security-relevant changes (anything touching `crypto/`, `internal/gpgutil`,
  `internal/sealer`, `internal/webhook`, or the recipient/fingerprint
  validation paths) should call that out explicitly in the PR description —
  see [SECURITY.md](SECURITY.md) for what counts as in-scope.

## Reporting bugs vs. vulnerabilities

- Regular bugs: open a GitHub issue.
- Suspected security vulnerabilities: **do not** open a public issue — follow
  [SECURITY.md](SECURITY.md)'s private disclosure process instead.

## Code of conduct

This project follows the [CNCF Code of Conduct](CODE_OF_CONDUCT.md).
