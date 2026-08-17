package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/OpScaleHub/git-secret/internal/cli"
)

func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		vals []string
		want string
	}{
		{[]string{"", "", "c"}, "c"},
		{[]string{"a", "b"}, "a"},
		{[]string{"", ""}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := firstNonEmpty(c.vals...); got != c.want {
			t.Errorf("firstNonEmpty(%v) = %q, want %q", c.vals, got, c.want)
		}
	}
}

func TestEnvMap(t *testing.T) {
	got := envMap([]string{"FOO=bar", "BAZ=qux=extra", "NOEQUALS"})
	if got["FOO"] != "bar" {
		t.Errorf("FOO = %q, want bar", got["FOO"])
	}
	if got["BAZ"] != "qux=extra" {
		t.Errorf("BAZ = %q, want qux=extra (only first '=' should split)", got["BAZ"])
	}
	if _, ok := got["NOEQUALS"]; ok {
		t.Errorf("expected an entry with no '=' to be skipped")
	}
}

func TestIsGitHubHost(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"git@github.com:OpScaleHub/git-secret.git", true},
		{"ssh://git@github.com/OpScaleHub/git-secret.git", true},
		{"git@gitlab.com:org/repo.git", false},
		{"ssh://git@example.com:2222/org/repo.git", false},
		{"https://github.com/OpScaleHub/git-secret.git", false}, // no '@' — not our concern, HTTPS doesn't use known_hosts
		{"file:///tmp/some/repo", false},
	}
	for _, c := range cases {
		if got := isGitHubHost(c.url); got != c.want {
			t.Errorf("isGitHubHost(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestWriteBuiltinKnownHostsIfGitHub(t *testing.T) {
	path, err := writeBuiltinKnownHostsIfGitHub("git@github.com:OpScaleHub/git-secret.git")
	if err != nil {
		t.Fatalf("writeBuiltinKnownHostsIfGitHub: %v", err)
	}
	defer os.Remove(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written known_hosts: %v", err)
	}
	if !strings.Contains(string(data), "github.com ssh-ed25519") {
		t.Fatalf("written known_hosts missing expected content: %s", data)
	}
}

func TestWriteBuiltinKnownHostsIfGitHub_NonGitHub(t *testing.T) {
	path, err := writeBuiltinKnownHostsIfGitHub("git@gitlab.com:org/repo.git")
	if err != nil {
		t.Fatalf("writeBuiltinKnownHostsIfGitHub: %v", err)
	}
	if path != "" {
		t.Fatalf("expected no known_hosts file for a non-GitHub host, got %q", path)
	}
}

func TestRun_MissingRequiredConfig(t *testing.T) {
	code := run([]string{"--repo-url=git@github.com:x/y.git"}, nil)
	if code != exitUsage {
		t.Fatalf("code = %d, want %d (missing gpg key + auth token)", code, exitUsage)
	}
}

func TestRun_NoArgsAtAll(t *testing.T) {
	code := run(nil, nil)
	if code != exitUsage {
		t.Fatalf("code = %d, want %d", code, exitUsage)
	}
}

func TestRun_Version(t *testing.T) {
	if code := run([]string{"--version"}, nil); code != 0 {
		t.Fatalf("--version exit code = %d, want 0", code)
	}
}

// --- End-to-end: build the real binary and run it as a subprocess,
// matching this repo's existing pattern (see cmd/kubectl-secret's
// buildKubectlSecret) of testing exactly what a user/operator would run.

func buildGitSecretServer(t *testing.T) string {
	t.Helper()
	name := "git-secret-server"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, "github.com/OpScaleHub/git-secret/cmd/git-secret-server")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build git-secret-server: %v\n%s", err, out)
	}
	return bin
}

func runGit(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}

// seedTestRepo mirrors internal/decryptserver's test fixture: a local
// git repo with one sealed k8s_secret_paths manifest, cloneable via a
// file:// URL so this test needs no network and no real deploy key.
func seedTestRepo(t *testing.T, value string) (repoPath, manifest string) {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "git", "init", "-q", "-b", "main")
	runGit(t, dir, "git", "config", "user.email", "test@example.com")
	runGit(t, dir, "git", "config", "user.name", "test")

	manifest = "deploy/api-secrets.yaml"
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
	key := make([]byte, 32)
	if err := os.WriteFile(filepath.Join(dir, ".repo-enc", "key"), []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	runGit(t, dir, "git", "add", ".")
	runGit(t, dir, "git", "commit", "-q", "-m", "seed")

	ctx, err := cli.LoadAt(dir)
	if err != nil {
		t.Fatalf("cli.LoadAt: %v", err)
	}
	encVal, err := ctx.EncryptK8sValue(manifest, "TOKEN", value)
	if err != nil {
		t.Fatalf("EncryptK8sValue: %v", err)
	}
	sealed := strings.Replace(skeleton, "TOKEN: PLACEHOLDER", "TOKEN: \""+encVal+"\"", 1)
	if err := os.WriteFile(full, []byte(sealed), 0o644); err != nil {
		t.Fatalf("write sealed manifest: %v", err)
	}
	runGit(t, dir, "git", "add", ".")
	runGit(t, dir, "git", "commit", "-q", "-m", "seal secret")
	return dir, manifest
}

// gpgIdentityFiles generates a throwaway GPG identity in its own
// isolated GNUPGHOME and returns the path to its exported armored
// private key — everything the real service's --gpg-private-key-file
// flag expects.
func gpgIdentityFiles(t *testing.T) (privateKeyPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// gpg-agent is unreliably reachable on GitHub's windows-latest
		// runners for unattended key generation — same CI environment
		// quirk internal/gpgutil's own tests already skip for, not a
		// limitation of this feature.
		t.Skip("gpg-agent unreliable on windows CI runners")
	}
	home := t.TempDir()
	gen := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-generate-key", "Test Server <test@example.com>", "default", "default", "never")
	gen.Env = append(os.Environ(), "GNUPGHOME="+home)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("gpg not usable in this environment, skipping: %v: %s", err, out)
	}
	list := exec.Command("gpg", "--batch", "--with-colons", "--list-secret-keys")
	list.Env = append(os.Environ(), "GNUPGHOME="+home)
	out, err := list.Output()
	if err != nil {
		t.Fatalf("list secret keys: %v", err)
	}
	var fpr string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			fields := strings.Split(line, ":")
			fpr = fields[9]
			break
		}
	}
	if fpr == "" {
		t.Fatalf("could not find fingerprint in: %s", out)
	}

	export := exec.Command("gpg", "--batch", "--armor", "--export-secret-keys", fpr)
	export.Env = append(os.Environ(), "GNUPGHOME="+home)
	armored, err := export.Output()
	if err != nil {
		t.Fatalf("export secret key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "private.asc")
	if err := os.WriteFile(path, armored, 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}
	return path
}

func TestEndToEnd_ServeAndDecrypt(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	bin := buildGitSecretServer(t)
	repoPath, manifest := seedTestRepo(t, "e2e-secret-value")
	gpgKeyPath := gpgIdentityFiles(t)

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("e2e-test-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	cmd := exec.Command(bin,
		"--repo-url=file://"+repoPath,
		"--listen-addr=127.0.0.1:18453",
		"--gpg-private-key-file="+gpgKeyPath,
		"--auth-token-file="+tokenPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	}()

	// Poll for the server to be up rather than a fixed sleep.
	var healthy bool
	for i := 0; i < 50; i++ {
		resp, err := http.Get("http://127.0.0.1:18453/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !healthy {
		t.Fatalf("server never became healthy; stderr:\n%s", stderr.String())
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:18453/decrypt?path="+manifest, nil)
	req.Header.Set("Authorization", "Bearer e2e-test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("decrypt request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; stderr:\n%s", resp.StatusCode, stderr.String())
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["TOKEN"] != "e2e-secret-value" {
		t.Fatalf("TOKEN = %q, want %q", got["TOKEN"], "e2e-secret-value")
	}

	// Graceful shutdown: SIGTERM should make the process exit 0, not
	// be killed.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("process exit after SIGTERM: %v; stderr:\n%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within 5s of SIGTERM")
	}
}
