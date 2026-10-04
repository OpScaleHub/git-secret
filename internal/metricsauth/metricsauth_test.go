package metricsauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// fakeAPI answers TokenReviews from tokens (token -> username; absent =
// unauthenticated) and SubjectAccessReviews from allow (username -> may
// GET /metrics), counting both.
type fakeAPI struct {
	tokens     map[string]string
	allow      map[string]bool
	tokenCalls int
	sarCalls   int
	lastSAR    authzv1.SubjectAccessReviewSpec
}

func (f *fakeAPI) client() *fake.Clientset {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		f.tokenCalls++
		tr := a.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		if user, ok := f.tokens[tr.Spec.Token]; ok {
			tr.Status = authnv1.TokenReviewStatus{Authenticated: true, User: authnv1.UserInfo{Username: user, Groups: []string{"g"}}}
		}
		return true, tr, nil
	})
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		f.sarCalls++
		sar := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		f.lastSAR = sar.Spec
		sar.Status.Allowed = f.allow[sar.Spec.User] &&
			sar.Spec.NonResourceAttributes != nil &&
			sar.Spec.NonResourceAttributes.Path == "/metrics" &&
			sar.Spec.NonResourceAttributes.Verb == "get"
		return true, sar, nil
	})
	return cs
}

func serve(t *testing.T, r *reviewer, authz string) int {
	t.Helper()
	h, err := r.filter(logr.Discard(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestFilter_Decisions(t *testing.T) {
	api := &fakeAPI{
		tokens: map[string]string{"scraper-token": "system:serviceaccount:monitoring:prometheus", "other-token": "someone"},
		allow:  map[string]bool{"system:serviceaccount:monitoring:prometheus": true},
	}
	r := newReviewer(api.client(), time.Minute, time.Now)

	cases := []struct {
		name, authz string
		want        int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"not bearer", "Basic Zm9vOmJhcg==", http.StatusUnauthorized},
		{"empty bearer", "Bearer ", http.StatusUnauthorized},
		{"unknown token", "Bearer nope", http.StatusUnauthorized},
		{"authenticated, not allowed", "Bearer other-token", http.StatusForbidden},
		{"authenticated and allowed", "Bearer scraper-token", http.StatusOK},
		{"scheme is case-insensitive", "bearer scraper-token", http.StatusOK},
	}
	for _, c := range cases {
		if got := serve(t, r, c.authz); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
	if api.lastSAR.User != "system:serviceaccount:monitoring:prometheus" || len(api.lastSAR.Groups) != 1 {
		t.Errorf("SubjectAccessReview did not carry the reviewed user: %+v", api.lastSAR)
	}
}

func TestFilter_CachesAllowOnlyUntilTTL(t *testing.T) {
	api := &fakeAPI{
		tokens: map[string]string{"t": "u", "denied": "d"},
		allow:  map[string]bool{"u": true},
	}
	now := time.Unix(1_000_000, 0)
	r := newReviewer(api.client(), time.Minute, func() time.Time { return now })

	serve(t, r, "Bearer t")
	serve(t, r, "Bearer t")
	if api.tokenCalls != 1 || api.sarCalls != 1 {
		t.Fatalf("second allowed scrape was re-reviewed: %d TokenReviews, %d SARs", api.tokenCalls, api.sarCalls)
	}

	now = now.Add(time.Minute + time.Second)
	serve(t, r, "Bearer t")
	if api.tokenCalls != 2 {
		t.Fatalf("allow decision outlived its TTL: %d TokenReviews", api.tokenCalls)
	}

	serve(t, r, "Bearer denied")
	serve(t, r, "Bearer denied")
	if api.sarCalls != 4 { // 2 for "t" (before and after the TTL) + 2 un-cached denials
		t.Fatalf("a denial was cached: %d SARs, want 4", api.sarCalls)
	}
}
