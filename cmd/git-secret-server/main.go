// Command git-secret-server runs the HTTP bridge an External Secrets
// Operator Webhook SecretStore calls to pull decrypted values out of a
// git-secret-protected repository. See internal/decryptserver for the
// request/response contract and internal/decryptserver's package doc
// for why every request gets its own fresh clone rather than a shared,
// periodically-refreshed checkout.
//
// Configuration is via flags or the equivalent environment variable
// (flag wins if both are set) — env vars are what a Kubernetes
// Deployment normally sets, flags are convenient for local runs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/OpScaleHub/git-secret/internal/decryptserver"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// githubKnownHosts pins SSH host-key verification for github.com, used
// as the default known_hosts content whenever --repo-url points at
// github.com and no --known-hosts-file is given explicitly. Sourced
// from GitHub's own published SSH key fingerprints:
// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
// — re-verify against that page if GitHub ever rotates these (a stale
// entry only ever fails a clone, via StrictHostKeyChecking=yes; it
// cannot itself downgrade to trusting an attacker's key instead, so
// this fails safe either way).
const githubKnownHosts = `github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=
`

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Environ()))
}

// config is the fully-resolved set of settings run needs, after
// flag/env merging and file reads — kept separate from flag parsing so
// the two are independently testable.
type config struct {
	repoURL        string
	repoRef        string
	listenAddr     string
	sshKeyPath     string
	knownHostsPath string
	gpgPrivateKey  []byte
	authToken      string
	cloneTimeout   time.Duration
}

func run(args []string, environ []string) int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	fs := flag.NewFlagSet("git-secret-server", flag.ContinueOnError)
	repoURL := fs.String("repo-url", "", "URL of the repository to serve decrypted values from (env REPO_URL)")
	repoRef := fs.String("repo-ref", "", "branch/tag to check out; empty uses the remote default (env REPO_REF)")
	listenAddr := fs.String("listen-addr", "", "address to listen on, e.g. :8080 (env LISTEN_ADDR, default :8080)")
	sshKeyFile := fs.String("ssh-key-file", "", "path to an SSH private key for repo read access, e.g. the same deploy key ArgoCD uses (env SSH_KEY_FILE)")
	knownHostsFile := fs.String("known-hosts-file", "", "path to a known_hosts file pinning the repo host's SSH key (env KNOWN_HOSTS_FILE; defaults to a built-in pin for github.com)")
	gpgPrivateKeyFile := fs.String("gpg-private-key-file", "", "path to this service's armored GPG private key, imported at startup (env GPG_PRIVATE_KEY_FILE)")
	authTokenFile := fs.String("auth-token-file", "", "path to a file containing the bearer token callers must present (env AUTH_TOKEN_FILE)")
	cloneTimeout := fs.String("clone-timeout", "", "max duration a single request's git clone may take, e.g. 30s (env CLONE_TIMEOUT, default 30s)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *showVersion {
		fmt.Println("git-secret-server", version)
		return 0
	}

	env := envMap(environ)
	cfg := config{
		repoURL:        firstNonEmpty(*repoURL, env["REPO_URL"]),
		repoRef:        firstNonEmpty(*repoRef, env["REPO_REF"]),
		listenAddr:     firstNonEmpty(*listenAddr, env["LISTEN_ADDR"], ":8080"),
		sshKeyPath:     firstNonEmpty(*sshKeyFile, env["SSH_KEY_FILE"]),
		knownHostsPath: firstNonEmpty(*knownHostsFile, env["KNOWN_HOSTS_FILE"]),
	}

	gpgKeyPath := firstNonEmpty(*gpgPrivateKeyFile, env["GPG_PRIVATE_KEY_FILE"])
	authTokenPath := firstNonEmpty(*authTokenFile, env["AUTH_TOKEN_FILE"])
	cloneTimeoutStr := firstNonEmpty(*cloneTimeout, env["CLONE_TIMEOUT"], "30s")

	var missing []string
	if cfg.repoURL == "" {
		missing = append(missing, "--repo-url/REPO_URL")
	}
	if gpgKeyPath == "" {
		missing = append(missing, "--gpg-private-key-file/GPG_PRIVATE_KEY_FILE")
	}
	if authTokenPath == "" {
		missing = append(missing, "--auth-token-file/AUTH_TOKEN_FILE")
	}
	if len(missing) > 0 {
		logger.Error("missing required configuration", "missing", missing)
		return exitUsage
	}

	timeout, err := time.ParseDuration(cloneTimeoutStr)
	if err != nil {
		logger.Error("invalid --clone-timeout/CLONE_TIMEOUT", "value", cloneTimeoutStr, "err", err)
		return exitUsage
	}
	cfg.cloneTimeout = timeout

	gpgKey, err := os.ReadFile(gpgKeyPath)
	if err != nil {
		logger.Error("read GPG private key file", "path", gpgKeyPath, "err", err)
		return exitError
	}
	cfg.gpgPrivateKey = gpgKey

	tokenRaw, err := os.ReadFile(authTokenPath)
	if err != nil {
		logger.Error("read auth token file", "path", authTokenPath, "err", err)
		return exitError
	}
	cfg.authToken = strings.TrimSpace(string(tokenRaw))
	if cfg.authToken == "" {
		logger.Error("auth token file is empty", "path", authTokenPath)
		return exitError
	}

	if cfg.sshKeyPath != "" && cfg.knownHostsPath == "" {
		if path, err := writeBuiltinKnownHostsIfGitHub(cfg.repoURL); err != nil {
			logger.Error("prepare known_hosts", "err", err)
			return exitError
		} else if path != "" {
			cfg.knownHostsPath = path
			logger.Info("using built-in known_hosts pin for github.com — verify it's current if this ever fails to clone")
		} else {
			logger.Warn("no --known-hosts-file given for a non-GitHub host — SSH host-key verification will trust-on-first-use (accept-new), not a pinned key")
		}
	}

	// An isolated, process-private GNUPGHOME — never the operator's own
	// keyring, and cleaned up on exit rather than left on disk holding
	// key material after the process ends.
	gnupgHome, err := os.MkdirTemp("", "git-secret-server-gnupg-*")
	if err != nil {
		logger.Error("create GNUPGHOME", "err", err)
		return exitError
	}
	defer os.RemoveAll(gnupgHome)
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		logger.Error("chmod GNUPGHOME", "err", err)
		return exitError
	}
	os.Setenv("GNUPGHOME", gnupgHome)

	if !gpgutil.Available() {
		logger.Error("gpg binary not found on PATH")
		return exitError
	}
	if err := gpgutil.ImportSecretKey(cfg.gpgPrivateKey); err != nil {
		logger.Error("import GPG private key", "err", err)
		return exitError
	}
	// The key material has done its job (it's now in gnupgHome, which
	// itself gets wiped on exit) — drop the in-memory copy rather than
	// holding it in cfg for the remainder of the process lifetime.
	for i := range cfg.gpgPrivateKey {
		cfg.gpgPrivateKey[i] = 0
	}
	cfg.gpgPrivateKey = nil

	srv := decryptserver.New(decryptserver.Config{
		RepoURL:        cfg.repoURL,
		RepoRef:        cfg.repoRef,
		SSHKeyPath:     cfg.sshKeyPath,
		KnownHostsPath: cfg.knownHostsPath,
		AuthToken:      cfg.authToken,
		CloneTimeout:   cfg.cloneTimeout,
		Logger:         logger,
	})

	httpServer := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No blanket WriteTimeout: a request's real bound is
		// CloneTimeout plus decrypt time, both well inside a normal
		// git clone, but a hard server-wide write deadline would cut
		// off a slow client read of a normal-sized response for no
		// good reason.
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.listenAddr, "repo", cfg.repoURL)
		serveErr <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
			return exitError
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "err", err)
			return exitError
		}
	}
	return 0
}

const (
	exitUsage = 2
	exitError = 1
)

// writeBuiltinKnownHostsIfGitHub returns a path to a temp file
// containing githubKnownHosts if repoURL's host is github.com, or ""
// (no error) for any other host — callers should fall back to
// accept-new (or require an explicit --known-hosts-file) in that case.
func writeBuiltinKnownHostsIfGitHub(repoURL string) (string, error) {
	if !isGitHubHost(repoURL) {
		return "", nil
	}
	f, err := os.CreateTemp("", "git-secret-server-known-hosts-*")
	if err != nil {
		return "", fmt.Errorf("create known_hosts temp file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(githubKnownHosts); err != nil {
		return "", fmt.Errorf("write known_hosts temp file: %w", err)
	}
	return f.Name(), nil
}

// isGitHubHost reports whether repoURL's host is exactly github.com,
// recognizing both the "git@github.com:org/repo.git" SCP-like form and
// an explicit ssh://git@github.com/org/repo.git URL.
func isGitHubHost(repoURL string) bool {
	rest, ok := strings.CutPrefix(repoURL, "ssh://")
	if ok {
		rest, _, _ = strings.Cut(rest, "/")
		_, host, hasAt := strings.Cut(rest, "@")
		if !hasAt {
			host = rest
		}
		host, _, _ = strings.Cut(host, ":")
		return host == "github.com"
	}
	if _, rest, hasAt := strings.Cut(repoURL, "@"); hasAt {
		host, _, _ := strings.Cut(rest, ":")
		return host == "github.com"
	}
	return false
}

// envMap converts a Go-style []string ("KEY=VALUE") environment slice
// (as os.Environ() returns, and as passed explicitly by run's caller
// for testability) into a map.
func envMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

// firstNonEmpty returns the first non-empty string among vals.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
