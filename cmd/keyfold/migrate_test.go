package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const preRenameManifests = `# sealed with git-secret-seal; group git-secret.opscalehub.io/v1alpha1 (comment: unchanged)
apiVersion: git-secret.opscalehub.io/v1alpha1
kind: GitSecret
metadata:
  name: app
  namespace: prod
  annotations:
    git-secret.opscalehub.io/recipient-roles: "AAAA:controller"
    "git-secret.opscalehub.io/source-revision": "4f2a1c9"
spec:
  encryptedData:
    K: UkVOQwEReGNoYWNoYTIwcG9seTEzMDVhcGlWZXJzaW9uOiBnaXQtc2VjcmV0
  recipients:
    - AAAA
---
apiVersion: v1
kind: Namespace
metadata:
  name: prod
  annotations:
    git-secret.opscalehub.io/required-recipients: "AAAA"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: notes
data:
  note: "the old group was git-secret.opscalehub.io/v1alpha1"
`

func TestMigrate_RewritesOnlyGroupPositions(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "envs", "prod")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "app.yaml")
	if err := os.WriteFile(path, []byte(preRenameManifests), 0o640); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "README.md") // not YAML: never touched
	if err := os.WriteFile(other, []byte("apiVersion: git-secret.opscalehub.io/v1alpha1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"migrate", "-f", dir, "--dry-run"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("dry run exit %d: %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != preRenameManifests {
		t.Fatal("--dry-run modified the file")
	}
	if !strings.Contains(stdout.String(), "would migrate 4 reference(s) in 1 of 1 file(s)") {
		t.Errorf("dry-run summary: %q", stdout.String())
	}

	stdout.Reset()
	if code := run([]string{"migrate", "-f", dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("migrate exit %d: %s", code, stderr.String())
	}
	got, _ := os.ReadFile(path)
	want := strings.NewReplacer(
		"apiVersion: git-secret.opscalehub.io/v1alpha1", "apiVersion: keyfold.opscalehub.io/v1alpha1",
		"    git-secret.opscalehub.io/recipient-roles:", "    keyfold.opscalehub.io/recipient-roles:",
		`    "git-secret.opscalehub.io/source-revision":`, `    "keyfold.opscalehub.io/source-revision":`,
		"    git-secret.opscalehub.io/required-recipients:", "    keyfold.opscalehub.io/required-recipients:",
	).Replace(preRenameManifests)
	if string(got) != want {
		t.Fatalf("migrated file differs from expected.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Errorf("file mode changed to %v", info.Mode().Perm())
	}
	if b, _ := os.ReadFile(other); !bytes.Contains(b, []byte("git-secret.opscalehub.io")) {
		t.Error("non-YAML file was rewritten")
	}

	stdout.Reset()
	run([]string{"migrate", "-f", path}, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "migrated 0 reference(s)") {
		t.Errorf("second run not a no-op: %q", stdout.String())
	}
}

func TestMigrate_RequiresPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"migrate"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("exit %d, want usage", code)
	}
}
