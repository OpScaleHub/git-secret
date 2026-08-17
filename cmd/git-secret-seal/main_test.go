package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

func genTestKey(t *testing.T, gnupgHome string) string {
	t.Helper()
	if !gpgutil.Available() {
		t.Skip("gpg binary not on PATH")
	}
	batch := `
Key-Type: EDDSA
Key-Curve: ed25519
Subkey-Type: ECDH
Subkey-Curve: cv25519
Name-Real: seal cli test
Name-Email: seal-cli-test@example.invalid
Expire-Date: 0
%no-protection
%commit
`
	cmd := exec.Command("gpg", "--batch", "--gen-key")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	cmd.Stdin = strings.NewReader(batch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gpg --gen-key: %v\n%s", err, out)
	}
	cmd = exec.Command("gpg", "--batch", "--with-colons", "--list-secret-keys")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("list-secret-keys: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			f := strings.Split(line, ":")
			if len(f) > 9 {
				return f[9]
			}
		}
	}
	t.Fatal("no fingerprint found after gen-key")
	return ""
}

func TestRun_LiteralsProduceDecryptableManifest(t *testing.T) {
	gnupgHome := t.TempDir()
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		t.Fatal(err)
	}
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--namespace", "downtime",
		"--name", "downtime-secrets",
		"--recipient", fpr,
		"--from-literal", "USERNAME=admin",
		"--from-literal", "PASSWORD=hunter2",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("run() = %d, stderr: %s", code, stderr.String())
	}

	var gs v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(stdout.Bytes(), &gs); err != nil {
		t.Fatalf("output is not a valid GitSecret manifest: %v\n%s", err, stdout.String())
	}
	if gs.Kind != "GitSecret" || gs.Name != "downtime-secrets" || gs.Namespace != "downtime" {
		t.Fatalf("unexpected manifest identity: %#v", gs.ObjectMeta)
	}
	if strings.Contains(stdout.String(), "hunter2") {
		t.Fatal("plaintext password leaked into manifest output")
	}

	data, err := sealer.Unseal("downtime", "downtime-secrets", gs.Spec)
	if err != nil {
		t.Fatalf("Unseal of the CLI's own output failed: %v", err)
	}
	if data["USERNAME"] != "admin" || data["PASSWORD"] != "hunter2" {
		t.Errorf("round-trip mismatch: %#v", data)
	}
}

func TestRun_FromSecretFile(t *testing.T) {
	gnupgHome := t.TempDir()
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		t.Fatal(err)
	}
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	secretYAML := `
apiVersion: v1
kind: Secret
metadata:
  name: downtime-secrets
  namespace: downtime
stringData:
  API_KEY: super-secret-value
`
	path := t.TempDir() + "/secret.yaml"
	if err := os.WriteFile(path, []byte(secretYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-f", path, "--recipient", fpr}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("run() = %d, stderr: %s", code, stderr.String())
	}

	var gs v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(stdout.Bytes(), &gs); err != nil {
		t.Fatalf("bad manifest: %v", err)
	}
	if gs.Name != "downtime-secrets" || gs.Namespace != "downtime" {
		t.Fatalf("namespace/name not inherited from Secret manifest: %#v", gs.ObjectMeta)
	}
	data, err := sealer.Unseal(gs.Namespace, gs.Name, gs.Spec)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if data["API_KEY"] != "super-secret-value" {
		t.Errorf("got %#v", data)
	}
}

func TestRun_Rewrap(t *testing.T) {
	homeA := t.TempDir()
	if err := os.Chmod(homeA, 0o700); err != nil {
		t.Fatal(err)
	}
	fprA := genTestKey(t, homeA)

	t.Setenv("GNUPGHOME", homeA)
	var sealOut, sealErr bytes.Buffer
	code := run([]string{
		"--namespace", "ns", "--name", "obj",
		"--recipient", fprA,
		"--from-literal", "K=v",
	}, &sealOut, &sealErr)
	if code != exitOK {
		t.Fatalf("seal run() = %d, stderr: %s", code, sealErr.String())
	}
	manifestPath := t.TempDir() + "/gitsecret.yaml"
	if err := os.WriteFile(manifestPath, sealOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	homeB := t.TempDir()
	if err := os.Chmod(homeB, 0o700); err != nil {
		t.Fatal(err)
	}
	fprB := genTestKey(t, homeB)
	pub := exportPublicKeyCLI(t, homeB, fprB)
	importPublicKeyCLI(t, homeA, pub)

	t.Setenv("GNUPGHOME", homeA)
	var rewrapOut, rewrapErr bytes.Buffer
	code = run([]string{"--rewrap", manifestPath, "--recipient", fprA, "--recipient", fprB}, &rewrapOut, &rewrapErr)
	if code != exitOK {
		t.Fatalf("rewrap run() = %d, stderr: %s", code, rewrapErr.String())
	}

	var rewrapped v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(rewrapOut.Bytes(), &rewrapped); err != nil {
		t.Fatalf("bad rewrapped manifest: %v", err)
	}

	var original v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(sealOut.Bytes(), &original); err != nil {
		t.Fatal(err)
	}
	if rewrapped.Spec.EncryptedData["K"] != original.Spec.EncryptedData["K"] {
		t.Fatal("rewrap changed encryptedData; it must only replace encryptedKey")
	}

	t.Setenv("GNUPGHOME", homeB)
	data, err := sealer.Unseal("ns", "obj", rewrapped.Spec)
	if err != nil {
		t.Fatalf("recipient B cannot decrypt after --rewrap: %v", err)
	}
	if data["K"] != "v" {
		t.Fatalf("got %#v", data)
	}
}

func exportPublicKeyCLI(t *testing.T, gnupgHome, fpr string) []byte {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--armor", "--export", fpr)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("export public key: %v", err)
	}
	return out
}

func importPublicKeyCLI(t *testing.T, gnupgHome string, armored []byte) {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--import")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	cmd.Stdin = strings.NewReader(string(armored))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("import public key: %v\n%s", err, out)
	}
}

func TestRun_MissingRecipientIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--namespace", "ns", "--name", "n", "--from-literal", "K=V"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("run() = %d, want exitUsage; stderr: %s", code, stderr.String())
	}
}
