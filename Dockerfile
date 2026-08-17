# git-secret-server: the HTTP bridge letting External Secrets Operator
# pull decrypted values out of a git-secret-protected repository. See
# internal/decryptserver for the request/response contract and the
# README's "git-secret-server" section for deployment.

FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/git-secret-server ./cmd/git-secret-server

# git and gpg are real runtime dependencies, not build-time-only —
# the server shells out to both on every request (see
# internal/gitutil.CloneContext and internal/gpgutil) — so this can't
# be a from-scratch/distroless-static image the way a pure-Go binary
# normally could be.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        gnupg \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Explicit numeric UID/GID, not just a named user: Kubernetes'
# runAsNonRoot: true (set by this project's own Helm chart) has to
# verify non-root *statically*, from the image alone, without running
# anything -- a USER directive that names an account rather than a
# numeric ID fails that check ("cannot verify user is non-root"), even
# though the account itself is genuinely non-root.
RUN groupadd --system --gid 1000 git-secret-server \
    && useradd --system --uid 1000 --gid 1000 --create-home --home-dir /home/git-secret-server --shell /usr/sbin/nologin git-secret-server
USER 1000:1000
WORKDIR /home/git-secret-server

COPY --from=build /out/git-secret-server /usr/local/bin/git-secret-server

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/git-secret-server"]
