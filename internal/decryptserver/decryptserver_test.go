package decryptserver

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpScaleHub/git-secret/internal/cli"
)

// testRepo creates a bare-ish local git repository (a real working
// checkout with a committed history, cloneable via a file:// URL — no
// network needed) whose k8s_secret_paths manifest is already sealed
// with a "file" backend key, and returns its filesystem path plus the
// path (repo-relative) to the sealed manifest.
func testRepo(t *testing.T, plainValue string) (repoPath, manifestPath string) {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q", "-b", "main")
	run(t, dir, "git", "config", "user.email", "test@example.com")
	run(t, dir, "git", "config", "user.name", "test")

	manifest := "deploy/api-secrets.yaml"
	full := filepath.Join(dir, manifest)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	skeleton := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: api-secrets\n  namespace: apps\nstringData:\n  TOKEN: PLACEHOLDER\n"
	if err := os.WriteFile(full, []byte(skeleton), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cfg := []byte("version: 1\nk8s_secret_paths:\n  - " + manifest + "\nkey_backend: file\nkey_source: .repo-enc/key\n")
	if err := os.WriteFile(filepath.Join(dir, ".repo-enc.yml"), cfg, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".repo-enc"), 0o755); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	// A fixed all-zero key, hex-encoded (FileBackend's on-disk format),
	// is fine for a hermetic test fixture — never do this for a real
	// repo.
	key := make([]byte, 32)
	if err := os.WriteFile(filepath.Join(dir, ".repo-enc", "key"), []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-q", "-m", "seed")

	ctx, err := cli.LoadAt(dir)
	if err != nil {
		t.Fatalf("cli.LoadAt: %v", err)
	}
	encVal, err := ctx.EncryptK8sValue(manifest, "TOKEN", plainValue)
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
	}
	sealed := strings.Replace(skeleton, "TOKEN: PLACEHOLDER", "TOKEN: \""+encVal+"\"", 1)
	if err := os.WriteFile(full, []byte(sealed), 0o644); err != nil {
		t.Fatalf("write sealed manifest: %v", err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-q", "-m", "seal secret")

	return dir, manifest
}

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}

func newTestServer(t *testing.T, repoPath, token string) *httptest.Server {
	t.Helper()
	srv := New(Config{
		RepoURL:   "file://" + repoPath,
		AuthToken: token,
	})
	return httptest.NewServer(srv.Handler())
}

func TestDecrypt_RoundTrip(t *testing.T) {
	repoPath, manifest := testRepo(t, "s3cr3t-value")
	ts := newTestServer(t, repoPath, "test-token")
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/decrypt?path="+manifest, nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["TOKEN"] != "s3cr3t-value" {
		t.Fatalf("TOKEN = %q, want %q", got["TOKEN"], "s3cr3t-value")
	}
}

func TestDecrypt_WrongToken(t *testing.T) {
	repoPath, manifest := testRepo(t, "s3cr3t-value")
	ts := newTestServer(t, repoPath, "test-token")
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/decrypt?path="+manifest, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestDecrypt_MissingToken(t *testing.T) {
	repoPath, manifest := testRepo(t, "s3cr3t-value")
	ts := newTestServer(t, repoPath, "test-token")
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/decrypt?path=" + manifest)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// An empty configured AuthToken must fail closed (reject everything),
// not open — see checkAuth's doc.
func TestDecrypt_EmptyConfiguredToken_RejectsEverything(t *testing.T) {
	repoPath, manifest := testRepo(t, "s3cr3t-value")
	ts := newTestServer(t, repoPath, "")
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/decrypt?path="+manifest, nil)
	req.Header.Set("Authorization", "Bearer ")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestDecrypt_MissingPathParam(t *testing.T) {
	repoPath, _ := testRepo(t, "s3cr3t-value")
	ts := newTestServer(t, repoPath, "test-token")
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/decrypt", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDecrypt_UnconfiguredPath_404(t *testing.T) {
	repoPath, _ := testRepo(t, "s3cr3t-value")
	ts := newTestServer(t, repoPath, "test-token")
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/decrypt?path=not/in/k8s_secret_paths.yaml", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// A path-traversal attempt must not escape the clone — Context.abs
// (already exercised by every other path-taking command) rejects it,
// and that rejection must surface as an ordinary error response here,
// not a panic or a file read outside the clone.
func TestDecrypt_PathTraversal_Rejected(t *testing.T) {
	repoPath, _ := testRepo(t, "s3cr3t-value")
	ts := newTestServer(t, repoPath, "test-token")
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/decrypt?path=../../../../etc/passwd", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (not configured in k8s_secret_paths)", resp.StatusCode)
	}
}

func TestDecrypt_HealthzUnauthenticated(t *testing.T) {
	repoPath, _ := testRepo(t, "s3cr3t-value")
	ts := newTestServer(t, repoPath, "test-token")
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// Each request must see the repo's *current* HEAD, not a stale cached
// clone from an earlier request — this is the whole point of cloning
// fresh per request instead of periodically re-pulling a shared
// checkout.
func TestDecrypt_SeesLatestCommit(t *testing.T) {
	repoPath, manifest := testRepo(t, "first-value")
	ts := newTestServer(t, repoPath, "test-token")
	defer ts.Close()

	get := func() string {
		req, _ := http.NewRequest("GET", ts.URL+"/decrypt?path="+manifest, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		var got map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return got["TOKEN"]
	}

	if v := get(); v != "first-value" {
		t.Fatalf("first read = %q, want %q", v, "first-value")
	}

	// Re-seal the same manifest with a new value and commit again.
	ctx, err := cli.LoadAt(repoPath)
	if err != nil {
		t.Fatalf("cli.LoadAt: %v", err)
	}
	full := filepath.Join(repoPath, manifest)
	skeleton := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: api-secrets\n  namespace: apps\nstringData:\n  TOKEN: PLACEHOLDER\n"
	if err := os.WriteFile(full, []byte(skeleton), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	encVal, err := ctx.EncryptK8sValue(manifest, "TOKEN", "second-value")
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
	}
	sealed := strings.Replace(skeleton, "TOKEN: PLACEHOLDER", "TOKEN: \""+encVal+"\"", 1)
	if err := os.WriteFile(full, []byte(sealed), 0o644); err != nil {
		t.Fatalf("write sealed manifest: %v", err)
	}
	run(t, repoPath, "git", "add", ".")
	run(t, repoPath, "git", "commit", "-q", "-m", "rotate")

	if v := get(); v != "second-value" {
		t.Fatalf("second read = %q, want %q (stale clone not refreshed)", v, "second-value")
	}
}

// TestDecrypt_ConcurrencyCap proves the server rejects (503) requests
// beyond MaxConcurrentClones rather than queuing them unboundedly — the
// mitigation for the resource-exhaustion risk of "every request does
// its own git clone" (see Config.MaxConcurrentClones's doc). Uses a
// clone that blocks (an unreachable host, timed via CloneTimeout) so
// concurrent requests reliably overlap instead of racing to finish
// before the next one starts.
func TestDecrypt_ConcurrencyCap(t *testing.T) {
	srv := New(Config{
		// 10.255.255.1 is a non-routable address chosen to hang/timeout
		// rather than fail instantly, so concurrent requests reliably
		// overlap in the clone phase.
		RepoURL:             "git://10.255.255.1/nonexistent.git",
		AuthToken:           "test-token",
		MaxConcurrentClones: 2,
		CloneTimeout:        3 * time.Second,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	get := func() int {
		req, _ := http.NewRequest("GET", ts.URL+"/decrypt?path=x", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("request: %v", err)
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	results := make(chan int, 3)
	for i := 0; i < 3; i++ {
		go func() { results <- get() }()
	}
	// Give the first two a head start into their (slow) clone phase
	// before the third arrives, so it reliably finds the semaphore full.
	time.Sleep(200 * time.Millisecond)
	third := get()
	if third != http.StatusServiceUnavailable {
		t.Fatalf("3rd concurrent request (over the cap of 2) = %d, want %d", third, http.StatusServiceUnavailable)
	}
	for i := 0; i < 3; i++ {
		<-results
	}
}
