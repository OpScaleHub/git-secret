package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildKubectlSecret compiles this binary once per test and returns the
// path to it, so these tests exercise exactly what a user would run.
func buildKubectlSecret(t *testing.T) string {
	t.Helper()
	name := "kubectl-secret"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, "github.com/OpScaleHub/git-secret/cmd/kubectl-secret")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build kubectl-secret: %v\n%s", err, out)
	}
	return bin
}

// buildGitSecret compiles the root git-secret binary, needed to bootstrap
// a test repo (init, key generation) the same way a real user would.
func buildGitSecret(t *testing.T) string {
	t.Helper()
	name := "git-secret"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, "github.com/OpScaleHub/git-secret")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build git-secret: %v\n%s", err, out)
	}
	return bin
}

func runBin(t *testing.T, bin, dir string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return out.String(), errBuf.String(), ee.ExitCode()
		}
		t.Fatalf("run %s %s: %v", bin, strings.Join(args, " "), err)
	}
	return out.String(), errBuf.String(), 0
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test")
	return dir
}

// writeStubKubectl writes a fake `kubectl` that copies stdin to
// receivedPath, so apply/create tests can assert on exactly what
// kubectl-secret piped to it without needing a real cluster in CI.
func writeStubKubectl(t *testing.T, receivedPath string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub kubectl is a POSIX shell script")
	}
	stubDir := t.TempDir()
	script := "#!/bin/sh\ncat > " + receivedPath + "\n"
	path := filepath.Join(stubDir, "kubectl")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub kubectl: %v", err)
	}
	return stubDir
}

func withOnPath(t *testing.T, dir string) {
	t.Helper()
	old := os.Getenv("PATH")
	os.Setenv("PATH", dir+string(os.PathListSeparator)+old)
	t.Cleanup(func() { os.Setenv("PATH", old) })
}

// addK8sSecretPath appends a k8s_secret_paths entry directly to an
// already-init'd repo's .repo-enc.yml. git-secret's own `init` command
// doesn't expose a flag for this field (out of scope for this change), so
// tests bootstrap with `git-secret init` and layer this on by hand.
func addK8sSecretPath(t *testing.T, root, relPath string) {
	t.Helper()
	cfgPath := filepath.Join(root, ".repo-enc.yml")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	data = append(data, []byte("k8s_secret_paths:\n  - \""+relPath+"\"\n")...)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeRepoFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	abs := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", relPath, err)
	}
}

func TestKubectlSecretHelpAndUnknownVerb(t *testing.T) {
	bin := buildKubectlSecret(t)
	dir := t.TempDir()

	out, _, code := runBin(t, bin, dir, "help")
	if code != 0 || !strings.Contains(out, "Usage: kubectl secret") {
		t.Fatalf("help: code=%d out=%q", code, out)
	}

	_, _, code = runBin(t, bin, dir)
	if code != 1 {
		t.Fatalf("no args: code=%d, want 1", code)
	}

	_, stderr, code := runBin(t, bin, dir, "bogus-verb")
	if code != 1 || !strings.Contains(stderr, "Unknown verb") {
		t.Fatalf("unknown verb: code=%d stderr=%q", code, stderr)
	}
}

func TestKubectlSecretEncryptValueThenView(t *testing.T) {
	gitSecretBin := buildGitSecret(t)
	kubectlSecretBin := buildKubectlSecret(t)
	repo := initGitRepo(t)

	if _, _, code := runBin(t, gitSecretBin, repo, "init", "secrets/**"); code != 0 {
		t.Fatalf("git-secret init failed")
	}
	addK8sSecretPath(t, repo, "deploy/app-secret.yaml")

	out, stderr, code := runBin(t, kubectlSecretBin, repo, "encrypt-value", "-f", "deploy/app-secret.yaml", "-k", "OIDC_CLIENT_SECRET", "s3cr3t-value")
	if code != 0 {
		t.Fatalf("encrypt-value: code=%d stderr=%q", code, stderr)
	}
	blob := strings.TrimSpace(out)
	if !strings.HasPrefix(blob, "repo-enc:v1:") {
		t.Fatalf("encrypt-value output = %q, want repo-enc:v1: prefix", blob)
	}

	manifest := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\nstringData:\n  OIDC_CLIENT_SECRET: \"" + blob + "\"\n  PLAIN_NOTE: not-a-secret\n"
	writeRepoFile(t, repo, "deploy/app-secret.yaml", manifest)

	out, stderr, code = runBin(t, kubectlSecretBin, repo, "view", "-f", "deploy/app-secret.yaml")
	if code != 0 {
		t.Fatalf("view: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(out, "s3cr3t-value") {
		t.Fatalf("view output missing decrypted value: %q", out)
	}
	if strings.Contains(out, "repo-enc:v1:") {
		t.Fatalf("view output still contains ciphertext marker: %q", out)
	}
	if !strings.Contains(out, "not-a-secret") {
		t.Fatalf("view output lost plaintext-already value: %q", out)
	}
}

func TestKubectlSecretApplyPipesDecryptedYAMLToKubectl(t *testing.T) {
	gitSecretBin := buildGitSecret(t)
	kubectlSecretBin := buildKubectlSecret(t)
	repo := initGitRepo(t)

	if _, _, code := runBin(t, gitSecretBin, repo, "init", "secrets/**"); code != 0 {
		t.Fatalf("git-secret init failed")
	}
	addK8sSecretPath(t, repo, "deploy/app-secret.yaml")

	out, _, code := runBin(t, kubectlSecretBin, repo, "encrypt-value", "-f", "deploy/app-secret.yaml", "-k", "OIDC_CLIENT_SECRET", "s3cr3t-value")
	if code != 0 {
		t.Fatalf("encrypt-value failed")
	}
	blob := strings.TrimSpace(out)
	manifest := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\nstringData:\n  OIDC_CLIENT_SECRET: \"" + blob + "\"\n"
	writeRepoFile(t, repo, "deploy/app-secret.yaml", manifest)

	received := filepath.Join(t.TempDir(), "received.yaml")
	stubDir := writeStubKubectl(t, received)
	withOnPath(t, stubDir)

	_, stderr, code := runBin(t, kubectlSecretBin, repo, "apply", "-f", "deploy/app-secret.yaml", "-n", "myns")
	if code != 0 {
		t.Fatalf("apply: code=%d stderr=%q", code, stderr)
	}

	data, err := os.ReadFile(received)
	if err != nil {
		t.Fatalf("read stub-received file (kubectl was never invoked?): %v", err)
	}
	if !strings.Contains(string(data), "s3cr3t-value") {
		t.Fatalf("stub kubectl did not receive decrypted manifest: %q", data)
	}
	if strings.Contains(string(data), "repo-enc:v1:") {
		t.Fatalf("stub kubectl received ciphertext instead of decrypted manifest: %q", data)
	}
}

func TestKubectlSecretRejectsFileNotInK8sSecretPaths(t *testing.T) {
	gitSecretBin := buildGitSecret(t)
	kubectlSecretBin := buildKubectlSecret(t)
	repo := initGitRepo(t)

	if _, _, code := runBin(t, gitSecretBin, repo, "init", "secrets/**"); code != 0 {
		t.Fatalf("git-secret init failed")
	}
	writeRepoFile(t, repo, "deploy/app-secret.yaml", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\nstringData:\n  PLAIN_NOTE: not-a-secret\n")

	_, stderr, code := runBin(t, kubectlSecretBin, repo, "view", "-f", "deploy/app-secret.yaml")
	if code == 0 {
		t.Fatalf("expected view to fail for a file not listed in k8s_secret_paths, stderr=%q", stderr)
	}
}
