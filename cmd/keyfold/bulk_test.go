package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpScaleHub/keyfold/api/v1alpha1"
	"github.com/OpScaleHub/keyfold/internal/gpgutil"
	"github.com/OpScaleHub/keyfold/internal/sealer"
)

// bulkFixture: operator A (the only secret key in GNUPGHOME) plus a new
// cluster C whose public key A does NOT have -- it arrives only through a
// keyring file, as for a recovery holder on an offline machine.
type bulkFixture struct {
	dir, homeA, homeC, fprA, fprC, keyring string
}

func newBulkFixture(t *testing.T) bulkFixture {
	t.Helper()
	f := bulkFixture{dir: t.TempDir()}
	f.homeA = shortTempDir(t)
	f.fprA = genTestKey(t, f.homeA)
	f.homeC = shortTempDir(t)
	f.fprC = genTestKey(t, f.homeC)
	pubC := exportPublicKeyCLI(t, f.homeC, f.fprC)
	pubA := exportPublicKeyCLI(t, f.homeA, f.fprA)

	f.keyring = filepath.Join(t.TempDir(), "keyring.yaml")
	indent := func(s string) string { return "      " + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n      ") }
	kr := "recipients:\n" +
		"  - fingerprint: " + f.fprA + "\n    role: recovery\n    publicKey: |\n" + indent(string(pubA)) + "\n" +
		"  - fingerprint: " + f.fprC + "\n    role: controller\n    publicKey: |\n" + indent(string(pubC)) + "\n"
	if err := os.WriteFile(f.keyring, []byte(kr), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GNUPGHOME", f.homeA)
	seal := func(name string, extra ...string) {
		args := append([]string{"seal", "--namespace", "prod", "--name", name, "--recipient", f.fprA, "--no-provenance", "--from-literal", "K=" + name}, extra...)
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitOK {
			t.Fatalf("seal %s: %s", name, errb.String())
		}
		if err := os.WriteFile(filepath.Join(f.dir, name+".yaml"), out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seal("a")
	seal("b")
	writeFile := func(name, body string) {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("configmap.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")
	writeFile("multi.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: y\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: z\n")
	return f
}

func TestRecipientsAdd_BulkViaKeyringPublicKeys(t *testing.T) {
	f := newBulkFixture(t)
	before := map[string]v1alpha1.GitSecret{}
	for _, n := range []string{"a", "b"} {
		before[n] = loadGS(t, mustRead(t, filepath.Join(f.dir, n+".yaml")))
	}

	var out, errb bytes.Buffer
	if code := run([]string{"recipients", "add", f.fprC, "-f", f.dir, "--role", "controller", "--dry-run", "--keyring", f.keyring}, &out, &errb); code != exitOK {
		t.Fatalf("dry-run = %d: %s", code, errb.String())
	}
	if strings.Contains(string(mustRead(t, filepath.Join(f.dir, "a.yaml"))), f.fprC) {
		t.Fatal("--dry-run wrote a file")
	}
	if !strings.Contains(out.String(), "would rewrap") {
		t.Errorf("dry-run output: %q", out.String())
	}

	out.Reset()
	if code := run([]string{"recipients", "add", f.fprC, "-f", f.dir, "--role", "controller", "--write", "--keyring", f.keyring}, &out, &errb); code != exitOK {
		t.Fatalf("add --write = %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "2 changed, 0 already done, 2 skipped") {
		t.Errorf("summary: %q", out.String())
	}
	if len(gpgutil.ExtraPublicKeyrings) != 0 {
		t.Error("scratch keyring left registered after the command")
	}

	for _, n := range []string{"a", "b"} {
		after := loadGS(t, mustRead(t, filepath.Join(f.dir, n+".yaml")))
		if len(after.Spec.Recipients) != 2 {
			t.Errorf("%s recipients = %v", n, after.Spec.Recipients)
		}
		for k, v := range before[n].Spec.EncryptedData {
			if after.Spec.EncryptedData[k] != v {
				t.Errorf("%s: encryptedData changed by a rewrap", n)
			}
		}
		t.Setenv("GNUPGHOME", f.homeC) // the new cluster decrypts on its own
		if got, err := sealer.Unseal("prod", n, after.Spec); err != nil || got["K"] != n {
			t.Errorf("new cluster cannot open %s: %v %v", n, got, err)
		}
		t.Setenv("GNUPGHOME", f.homeA)
	}
	// Operator's own keyring never gained C's public key.
	if _, err := gpgutil.ExportPublicKey(f.fprC); err == nil {
		t.Error("--keyring imported the new key into the operator's keyring")
	}

	out.Reset()
	run([]string{"recipients", "add", f.fprC, "-f", f.dir, "--write", "--keyring", f.keyring}, &out, &errb)
	if !strings.Contains(out.String(), "0 changed, 2 already done") {
		t.Errorf("second run not idempotent: %q", out.String())
	}

	out.Reset()
	if code := run([]string{"recipients", "list", "-f", f.dir}, &out, &errb); code != exitOK || strings.Count(out.String(), "\n") != 4 {
		t.Errorf("bulk list = %d:\n%s", code, out.String())
	}
}

// TestRecipientsBulk_AllOrNothing: one object this operator cannot open
// aborts the whole run before any file is written.
func TestRecipientsBulk_AllOrNothing(t *testing.T) {
	f := newBulkFixture(t)
	homeD := shortTempDir(t) // an unrelated identity: A cannot open its objects
	fprD := genTestKey(t, homeD)
	t.Setenv("GNUPGHOME", homeD)
	var out, errb bytes.Buffer
	if code := run([]string{"seal", "--namespace", "prod", "--name", "c-only", "--recipient", fprD, "--no-provenance", "--from-literal", "K=v"}, &out, &errb); code != exitOK {
		t.Fatalf("seal c-only: %s", errb.String())
	}
	os.WriteFile(filepath.Join(f.dir, "c-only.yaml"), out.Bytes(), 0o644)
	snapshot := map[string][]byte{}
	for _, n := range []string{"a", "b", "c-only"} {
		snapshot[n] = mustRead(t, filepath.Join(f.dir, n+".yaml"))
	}

	t.Setenv("GNUPGHOME", f.homeA)
	out.Reset()
	errb.Reset()
	if code := run([]string{"recipients", "add", f.fprC, "-f", f.dir, "--write", "--keyring", f.keyring}, &out, &errb); code != exitError {
		t.Fatalf("expected failure, got %d", code)
	}
	if !strings.Contains(errb.String(), "c-only.yaml") || !strings.Contains(errb.String(), "nothing written") {
		t.Errorf("stderr: %q", errb.String())
	}
	for _, n := range []string{"a", "b"} {
		if !bytes.Equal(mustRead(t, filepath.Join(f.dir, n+".yaml")), snapshot[n]) {
			t.Errorf("%s.yaml was written despite another file failing", n)
		}
	}

	// Several files without --write is a usage error.
	if code := run([]string{"recipients", "add", f.fprC, "-f", filepath.Join(f.dir, "a.yaml"), "-f", filepath.Join(f.dir, "b.yaml")}, &out, &errb); code != exitUsage {
		t.Errorf("multi-file without --write = %d, want usage", code)
	}
}

func TestRecipients_KeyringRejectsMismatchedPublicKey(t *testing.T) {
	f := newBulkFixture(t)
	kr := mustRead(t, f.keyring)
	// Claim C's fingerprint for A's key block and vice versa.
	swapped := strings.Replace(strings.Replace(string(kr), f.fprA, "TMPFPR", 1), f.fprC, f.fprA, 1)
	swapped = strings.Replace(swapped, "TMPFPR", f.fprC, 1)
	os.WriteFile(f.keyring, []byte(swapped), 0o644)

	var out, errb bytes.Buffer
	if code := run([]string{"recipients", "add", f.fprC, "-f", filepath.Join(f.dir, "a.yaml"), "--keyring", f.keyring}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "not exactly that key") {
		t.Fatalf("mismatched publicKey accepted: %d %q", code, errb.String())
	}
}
