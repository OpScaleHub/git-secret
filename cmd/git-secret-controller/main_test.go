package main

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// TestPrintPublicKey exercises the --print-public-key path, which imports
// the configured private key and prints only its fingerprint + armored
// PUBLIC key, without ever contacting a cluster.
func TestPrintPublicKey(t *testing.T) {
	if !gpgutil.Available() {
		t.Skip("gpg not installed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("gpg-agent unreliable on windows CI runners")
	}

	home, err := os.MkdirTemp("/tmp", "gsc-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })

	gen := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-generate-key", "ctrl test <ctrl-test@example.invalid>", "default", "default", "never")
	gen.Env = append(os.Environ(), "GNUPGHOME="+home)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("gpg key generation not usable here: %v: %s", err, out)
	}
	exp := exec.Command("gpg", "--batch", "--armor", "--export-secret-keys")
	exp.Env = append(os.Environ(), "GNUPGHOME="+home)
	priv, err := exp.Output()
	if err != nil {
		t.Fatalf("export secret key: %v", err)
	}
	keyPath := t.TempDir() + "/key.asc"
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}

	// run() imports the secret key into a fresh GNUPGHOME, which needs a
	// working gpg-agent -- not reliably available on hosted CI runners
	// (macOS/Windows especially). Preflight the exact same operation and
	// skip rather than fail when the agent can't be reached, matching how
	// the sealer/gpgutil suites guard their gpg-dependent tests.
	pre, err := os.MkdirTemp("/tmp", "gsc-preflight-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(pre) })
	imp := exec.Command("gpg", "--batch", "--import")
	imp.Env = append(os.Environ(), "GNUPGHOME="+pre)
	imp.Stdin = bytes.NewReader(priv)
	if out, err := imp.CombinedOutput(); err != nil || bytes.Contains(out, []byte("No agent running")) {
		t.Skipf("gpg secret-key import not usable in this environment, skipping: %v: %s", err, out)
	}

	// Capture stdout.
	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	code := run([]string{"--gpg-private-key-file", keyPath, "--print-public-key"}, os.Environ())
	w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if code != 0 {
		t.Fatalf("run() = %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("output has no armored public key:\n%s", out)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("output leaked private key material")
	}
	// First line is the fingerprint (40 hex).
	first := strings.SplitN(strings.TrimSpace(out), "\n", 2)[0]
	if len(first) != 40 {
		t.Fatalf("first line is not a 40-hex fingerprint: %q", first)
	}
}
