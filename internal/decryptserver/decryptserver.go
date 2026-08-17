// Package decryptserver implements the HTTP surface an External Secrets
// Operator Webhook SecretStore calls to pull decrypted values out of a
// git-secret-protected repository. It exists so ESO's own
// reconcile/drift-detection/status machinery can manage the resulting
// Kubernetes Secret directly, without ArgoCD's own sync pipeline ever
// handling plaintext or decryption key material.
//
// Every request gets its own fresh, isolated `git clone` into a unique
// temp directory rather than a shared checkout kept up to date by a
// background poller: concurrent requests can never observe each other's
// half-updated tree, every response reflects exactly the remote's
// current HEAD, and there's no separate "keep it fresh" process to run
// or monitor. The tradeoff is a clone on every request instead of a
// cached one — acceptable given ESO's own reconcile interval is minutes,
// not sub-second.
package decryptserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpScaleHub/git-secret/internal/cli"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
	"gopkg.in/yaml.v3"
)

// Config configures a Server.
type Config struct {
	// RepoURL is the repository Server clones fresh on every request.
	// Any URL `git clone` accepts.
	RepoURL string
	// RepoRef is the branch/tag to check out. Empty uses the remote's
	// default branch.
	RepoRef string
	// SSHKeyPath, if set, authenticates the clone as this identity
	// (see gitutil.CloneOptions.SSHKeyPath) — e.g. the same deploy key
	// ArgoCD's own repo-server already uses for read access. Sharing
	// that key here carries no extra risk: the repository only ever
	// holds ciphertext, never plaintext, so read access to it is not
	// by itself access to any secret value.
	SSHKeyPath string
	// KnownHostsPath pins SSH host-key verification for the clone (see
	// gitutil.CloneOptions.KnownHostsPath). Strongly recommended
	// whenever SSHKeyPath is set.
	KnownHostsPath string
	// AuthToken must be presented as "Authorization: Bearer <token>"
	// on every request, compared in constant time. Required — a
	// Server built with an empty AuthToken authenticates nothing (see
	// checkAuth), refusing every request rather than silently
	// accepting all of them.
	AuthToken string
	// CloneTimeout bounds how long a single request's git clone may
	// take. Zero means bounded only by the request's own context
	// (e.g. the client disconnecting).
	CloneTimeout time.Duration
	// MaxConcurrentClones caps how many requests may be cloning at
	// once. Every request does its own `git clone` (see the package
	// doc), which is real CPU/disk/process cost — without a cap, an
	// authenticated caller (or a leaked token) sending many concurrent
	// requests could exhaust the pod's resources. Zero uses
	// defaultMaxConcurrentClones. A request that arrives once the cap
	// is already full gets an immediate 503 rather than queuing —
	// ESO's own reconcile loop retries on its normal schedule, so
	// failing fast is preferable to piling up unbounded in-flight
	// clones behind a queue.
	MaxConcurrentClones int
	// Logger receives one structured record per request (method, path
	// parameter, status, duration) and any error detail. Never
	// receives a decrypted value or the Authorization header. Defaults
	// to slog.Default() if nil.
	Logger *slog.Logger
}

// defaultMaxConcurrentClones is deliberately small — this service is
// meant to serve one ESO controller's reconcile traffic, not act as a
// general-purpose high-throughput API.
const defaultMaxConcurrentClones = 4

// Server answers ESO's Webhook SecretStore calls. See DecryptHandler's
// doc for the exact request/response contract.
type Server struct {
	cfg Config
	sem chan struct{}
}

// New constructs a Server. It does not start listening — call
// http.ListenAndServe(addr, srv.Handler()) or similar.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxConcurrentClones <= 0 {
		cfg.MaxConcurrentClones = defaultMaxConcurrentClones
	}
	return &Server{cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrentClones)}
}

// Handler returns the http.Handler serving /healthz (unauthenticated,
// for k8s liveness/readiness probes — never touches git or the
// decryption key) and /decrypt (see DecryptHandler's doc).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /decrypt", s.withLogging(s.handleDecrypt))
	return mux
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleDecrypt is the request/response contract ESO's generic Webhook
// SecretStore provider is configured against:
//
//	GET /decrypt?path=<repo-relative manifest path>[&namespace=<override>]
//	Authorization: Bearer <token>
//
//	200 application/json  -> flat {"key": "value", ...} of every
//	                          decrypted stringData entry — designed to
//	                          be consumed with ESO's dataFrom.extract
//	                          (jsonPath "$"), matching
//	                          DecryptK8sManifest's own whole-manifest
//	                          granularity.
//	401                    -> missing/wrong Authorization header.
//	400                    -> missing 'path' query parameter.
//	404                    -> path isn't opted into k8s_secret_paths,
//	                          or doesn't exist in this clone (matches
//	                          ESO's own documented deletionPolicy
//	                          trigger on 404).
//	502                    -> clone or decryption failed for any other
//	                          reason (bad credentials, corrupt
//	                          ciphertext, no key available, etc.).
//
// Every error response body is a generic, fixed message — full detail
// goes only to Config.Logger, server-side. This endpoint sits behind
// Config.AuthToken, so the risk of a detailed error aiding an attacker
// is lower than a fully public endpoint, but there's no reason to leak
// internal paths or crypto error detail to *any* caller by default.
func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := r.URL.Query().Get("path")
	if path == "" {
		writeError(w, http.StatusBadRequest, "missing required 'path' query parameter")
		return
	}
	namespace := r.URL.Query().Get("namespace")

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		writeError(w, http.StatusServiceUnavailable, "too many concurrent requests")
		return
	}

	workDir, err := os.MkdirTemp("", "git-secret-server-*")
	if err != nil {
		s.cfg.Logger.Error("mkdtemp failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer os.RemoveAll(workDir)

	cloneCtx := r.Context()
	if s.cfg.CloneTimeout > 0 {
		var cancel context.CancelFunc
		cloneCtx, cancel = context.WithTimeout(cloneCtx, s.cfg.CloneTimeout)
		defer cancel()
	}
	repoDir := filepath.Join(workDir, "repo")
	if err := gitutil.CloneContext(cloneCtx, gitutil.CloneOptions{
		URL:            s.cfg.RepoURL,
		Ref:            s.cfg.RepoRef,
		Dir:            repoDir,
		SSHKeyPath:     s.cfg.SSHKeyPath,
		KnownHostsPath: s.cfg.KnownHostsPath,
	}); err != nil {
		s.cfg.Logger.Error("clone failed", "err", err)
		writeError(w, http.StatusBadGateway, "could not fetch source repository")
		return
	}

	ctx, err := cli.LoadAt(repoDir)
	if err != nil {
		s.cfg.Logger.Error("load repo config failed", "err", err)
		writeError(w, http.StatusBadGateway, "repository is not configured for decryption")
		return
	}

	if !ctx.IsK8sSecretPath(path) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	decrypted, err := ctx.DecryptK8sManifest(path, namespace)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.cfg.Logger.Error("decrypt failed", "path", path, "err", err)
		writeError(w, http.StatusBadGateway, "decryption failed")
		return
	}

	values, err := stringDataToMap(decrypted)
	if err != nil {
		s.cfg.Logger.Error("parse decrypted manifest failed", "path", path, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(values); err != nil {
		s.cfg.Logger.Error("write response failed", "err", err)
	}
}

// checkAuth reports whether r carries the configured bearer token.
// s.cfg.AuthToken == "" always fails closed — an unconfigured token
// means "authenticate nothing," never "accept everything" — so a
// misconfigured deployment fails loudly (every request 401s) rather
// than silently serving decrypted secrets to anyone who can reach it.
func (s *Server) checkAuth(r *http.Request) bool {
	if s.cfg.AuthToken == "" {
		return false
	}
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	presented := strings.TrimPrefix(auth, prefix)
	// Constant-time so response timing can't be used to recover the
	// token one byte at a time.
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.AuthToken)) == 1
}

// manifestStringData is the one field DecryptK8sManifest's output is
// parsed back into — the decrypted values, keyed by their stringData
// name, ready to hand to ESO's dataFrom.extract as-is.
type manifestStringData struct {
	StringData map[string]string `yaml:"stringData"`
}

func stringDataToMap(manifest []byte) (map[string]string, error) {
	var m manifestStringData
	if err := yaml.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("decryptserver: parse decrypted manifest: %w", err)
	}
	if len(m.StringData) == 0 {
		return nil, fmt.Errorf("decryptserver: decrypted manifest has no stringData")
	}
	return m.StringData, nil
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// statusWriter captures the status code a handler actually wrote, for
// withLogging to report — http.ResponseWriter itself exposes no way to
// read this back.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// withLogging logs one record per request: method, the requested path
// parameter (a repo-relative manifest path — not sensitive), status,
// and duration. Deliberately never logs the Authorization header or any
// decrypted value.
func (s *Server) withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next(sw, r)
		s.cfg.Logger.Info("request",
			"method", r.Method,
			"path", r.URL.Query().Get("path"),
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	}
}
