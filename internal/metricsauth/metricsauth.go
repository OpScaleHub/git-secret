// Package metricsauth guards the controller's /metrics endpoint with the
// apiserver's own authentication and authorization: the caller's bearer
// token goes to a TokenReview, the resulting user to a
// SubjectAccessReview for the requested non-resource URL (e.g. GET
// /metrics). It is the same check controller-runtime's
// metrics/filters.WithAuthenticationAndAuthorization performs, built on
// client-go alone -- that package pulls in k8s.io/apiserver (gRPC,
// OpenTelemetry, CEL; +60% binary size), a poor trade for a controller
// whose value is a small, auditable footprint.
package metricsauth

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// cacheTTL bounds how long an allowed decision is reused: a scraper hits
// /metrics every 15-60s, and re-reviewing each scrape would be two API
// calls per scrape for no benefit. Denials are never cached.
const cacheTTL = time.Minute

// maxCacheEntries bounds memory if many distinct tokens are presented.
const maxCacheEntries = 256

// reviewTimeout bounds the TokenReview + SubjectAccessReview round trip.
const reviewTimeout = 10 * time.Second

// FilterProvider is a controller-runtime metrics server.Options.FilterProvider.
func FilterProvider(c *rest.Config, hc *http.Client) (server.Filter, error) {
	cs, err := kubernetes.NewForConfigAndClient(c, hc)
	if err != nil {
		return nil, err
	}
	return newReviewer(cs, cacheTTL, time.Now).filter, nil
}

type reviewer struct {
	client kubernetes.Interface
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	allowed map[[32]byte]time.Time // sha256(token + " " + verb + " " + path) -> expiry
}

func newReviewer(client kubernetes.Interface, ttl time.Duration, now func() time.Time) *reviewer {
	return &reviewer{client: client, ttl: ttl, now: now, allowed: map[[32]byte]time.Time{}}
}

func (r *reviewer) filter(log logr.Logger, next http.Handler) (http.Handler, error) {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token, ok := bearerToken(req)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		verb := strings.ToLower(req.Method)
		code, err := r.authorize(req.Context(), token, verb, req.URL.Path)
		if err != nil {
			log.Error(err, "metrics authorization review failed")
		}
		if code != http.StatusOK {
			http.Error(w, http.StatusText(code), code)
			return
		}
		next.ServeHTTP(w, req)
	}), nil
}

// authorize returns 200, 401 (not authenticated) or 403 (not allowed).
// Review errors fail closed as 401/403 with the error returned for logging.
func (r *reviewer) authorize(ctx context.Context, token, verb, path string) (int, error) {
	key := sha256.Sum256([]byte(token + " " + verb + " " + path))
	if r.cached(key) {
		return http.StatusOK, nil
	}

	ctx, cancel := context.WithTimeout(ctx, reviewTimeout)
	defer cancel()

	tr, err := r.client.AuthenticationV1().TokenReviews().Create(ctx,
		&authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}}, metav1.CreateOptions{})
	if err != nil {
		return http.StatusUnauthorized, err
	}
	if !tr.Status.Authenticated {
		return http.StatusUnauthorized, nil
	}

	u := tr.Status.User
	extra := make(map[string]authzv1.ExtraValue, len(u.Extra))
	for k, v := range u.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}
	sar, err := r.client.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:                  u.Username,
			UID:                   u.UID,
			Groups:                u.Groups,
			Extra:                 extra,
			NonResourceAttributes: &authzv1.NonResourceAttributes{Path: path, Verb: verb},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return http.StatusForbidden, err
	}
	if !sar.Status.Allowed {
		return http.StatusForbidden, nil
	}
	r.remember(key)
	return http.StatusOK, nil
}

func (r *reviewer) cached(key [32]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.allowed[key]
	if ok && r.now().Before(exp) {
		return true
	}
	delete(r.allowed, key)
	return false
}

func (r *reviewer) remember(key [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if len(r.allowed) >= maxCacheEntries {
		for k, exp := range r.allowed {
			if !now.Before(exp) {
				delete(r.allowed, k)
			}
		}
		if len(r.allowed) >= maxCacheEntries {
			r.allowed = map[[32]byte]time.Time{}
		}
	}
	r.allowed[key] = now.Add(r.ttl)
}

func bearerToken(req *http.Request) (string, bool) {
	h := req.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	return token, token != ""
}
