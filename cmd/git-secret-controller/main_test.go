package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// TestPrintPublicKey exercises the --print-public-key path, which imports
// the configured private key and prints only its fingerprint + armored
// PUBLIC key, without ever contacting a cluster.
func TestPrintPublicKey(t *testing.T) {
	if !gpgutil.Available() {
		t.Skip("gpg not installed")
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// run() imports a secret key into a fresh GNUPGHOME, which needs a
		// working gpg-agent -- not reliably spawnable on the hosted
		// macOS/Windows runners (the sealer/gpgutil suites skip these for
		// the same reason). Linux CI + local dev cover this path.
		t.Skipf("gpg-agent unreliable on %s CI runners", runtime.GOOS)
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

func TestServePubKey(t *testing.T) {
	const fpr = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
	pub := []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- servePubKey("127.0.0.1:38217", fpr, pub).Start(ctx) }()

	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://127.0.0.1:38217/pubkey")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server never came up: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(got), fpr+"\n") || !strings.Contains(string(got), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("unexpected /pubkey body: %q", got)
	}

	r2, err := http.Post("http://127.0.0.1:38217/pubkey", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /pubkey = %d, want 405", r2.StatusCode)
	}
	if r3, _ := http.Get("http://127.0.0.1:38217/nope"); r3.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /nope = %d, want 404", r3.StatusCode)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("server exited with error: %v", err)
	}
}
