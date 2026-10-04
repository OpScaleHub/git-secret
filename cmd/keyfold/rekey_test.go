package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/keyfold/api/v1alpha1"
	"github.com/OpScaleHub/keyfold/internal/sealer"
)

func loadGS(t *testing.T, b []byte) v1alpha1.GitSecret {
	t.Helper()
	var gs v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(b, &gs); err != nil {
		t.Fatalf("parse manifest: %v\n%s", err, b)
	}
	return gs
}

// TestRekey_FreshContentKeyLocksOutTheOldOne: values are unchanged, every
// ciphertext and the wrapped key change, roles/target survive, and the
// *old* content key (what a removed recipient may have kept) opens none of
// the new values.
func TestRekey_FreshContentKeyLocksOutTheOldOne(t *testing.T) {
	path, homeA, homeB, fprA, _ := sealForUnseal(t)
	before := loadGS(t, mustRead(t, path))
	before.Annotations = map[string]string{v1alpha1.RecipientRolesAnnotation: fprA + ":human"}
	before.Spec.Target.Name = "db-target"
	writeGS(t, path, before)

	t.Setenv("GNUPGHOME", homeA)
	var out, errb bytes.Buffer
	if code := run([]string{"rekey", "-f", path}, &out, &errb); code != exitOK {
		t.Fatalf("rekey = %d: %s", code, errb.String())
	}
	after := loadGS(t, out.Bytes())

	if after.Spec.EncryptedKey == before.Spec.EncryptedKey {
		t.Error("encryptedKey unchanged: no new content key")
	}
	for k, v := range before.Spec.EncryptedData {
		if after.Spec.EncryptedData[k] == v {
			t.Errorf("%s ciphertext unchanged", k)
		}
	}
	if after.Annotations[v1alpha1.RecipientRolesAnnotation] != fprA+":human" || after.Spec.Target.Name != "db-target" {
		t.Errorf("roles/target not preserved: %v / %+v", after.Annotations, after.Spec.Target)
	}

	t.Setenv("GNUPGHOME", homeB) // the other recipient still reads the same values
	got, err := sealer.Unseal("prod", "db", after.Spec)
	if err != nil || got["DB_PASSWORD"] != "it's s3cret" || got["NOTE"] != "line1\nline2" {
		t.Fatalf("values after rekey = %#v, %v", got, err)
	}

	stale := after.Spec
	stale.EncryptedKey = before.Spec.EncryptedKey // the content key someone may have kept
	if _, err := sealer.Unseal("prod", "db", stale); err == nil {
		t.Fatal("the old content key still opens values after rekey")
	}
}

// TestSet_ChangesOneValueWithoutReenteringTheRest.
func TestSet_ChangesOneValueWithoutReenteringTheRest(t *testing.T) {
	path, homeA, homeB, _, _ := sealForUnseal(t)
	valueFile := t.TempDir() + "/v"
	if err := os.WriteFile(valueFile, []byte("rotated-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := loadGS(t, mustRead(t, path))

	t.Setenv("GNUPGHOME", homeA)
	var out, errb bytes.Buffer
	if code := run([]string{"set", "DB_PASSWORD", "-f", path, "--value-file", valueFile, "--no-provenance"}, &out, &errb); code != exitOK {
		t.Fatalf("set = %d: %s", code, errb.String())
	}
	if strings.Contains(out.String(), "rotated-password") {
		t.Fatal("plaintext leaked into the manifest")
	}
	after := loadGS(t, out.Bytes())
	if after.Spec.EncryptedKey == before.Spec.EncryptedKey {
		t.Error("set did not use a fresh content key")
	}
	if len(after.Spec.Recipients) != len(before.Spec.Recipients) {
		t.Errorf("recipients changed: %v -> %v", before.Spec.Recipients, after.Spec.Recipients)
	}

	t.Setenv("GNUPGHOME", homeB)
	got, err := sealer.Unseal("prod", "db", after.Spec)
	if err != nil || got["DB_PASSWORD"] != "rotated-password" || got["NOTE"] != "line1\nline2" {
		t.Fatalf("values after set = %#v, %v", got, err)
	}

	// Adding a new key works the same way.
	path2 := t.TempDir() + "/db2.yaml"
	if err := os.WriteFile(path2, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	t.Setenv("GNUPGHOME", homeA)
	if code := run([]string{"set", "API_TOKEN", "-f", path2, "--value-file", valueFile, "--no-provenance"}, &out, &errb); code != exitOK {
		t.Fatalf("set new key = %d: %s", code, errb.String())
	}
	if n := len(loadGS(t, out.Bytes()).Spec.EncryptedData); n != 3 {
		t.Errorf("entries after adding a key = %d, want 3", n)
	}
}

func TestRekeySet_NonRecipientAndUsage(t *testing.T) {
	path, _, _, fprA, _ := sealForUnseal(t)
	outsider := shortTempDir(t)
	genTestKey(t, outsider)
	t.Setenv("GNUPGHOME", outsider)
	var out, errb bytes.Buffer
	if code := run([]string{"rekey", "-f", path}, &out, &errb); code != exitError || !strings.Contains(errb.String(), fprA) || out.Len() != 0 {
		t.Errorf("rekey as outsider: code %d, stderr %q, stdout %d bytes", code, errb.String(), out.Len())
	}
	for _, args := range [][]string{{"rekey"}, {"set"}, {"set", "K"}, {"set", "K", "-f", "-"}} {
		if code := run(args, &out, &errb); code != exitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeGS(t *testing.T, p string, gs v1alpha1.GitSecret) {
	t.Helper()
	b, err := sigsyaml.Marshal(gs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRekey_PublicKeysFromKeyring: the operator's keyring lacks the other
// recipient's public key; --keyring supplies it for this run only.
func TestRekey_PublicKeysFromKeyring(t *testing.T) {
	f := newBulkFixture(t) // A holds only its own key; C's public key lives only in the keyring file
	var out, errb bytes.Buffer
	if code := run([]string{"seal", "--namespace", "prod", "--name", "x", "--keyring", f.keyring, "--no-provenance", "--from-literal", "K=v"}, &out, &errb); code != exitOK {
		t.Fatalf("seal via keyring: %s", errb.String())
	}
	path := t.TempDir() + "/x.yaml"
	os.WriteFile(path, out.Bytes(), 0o644)

	out.Reset()
	errb.Reset()
	if code := run([]string{"rekey", "-f", path}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "--keyring") {
		t.Fatalf("rekey without the other public key: %d %q", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"rekey", "-f", path, "--keyring", f.keyring}, &out, &errb); code != exitOK {
		t.Fatalf("rekey --keyring = %d: %s", code, errb.String())
	}
	t.Setenv("GNUPGHOME", f.homeC)
	if got, err := sealer.Unseal("prod", "x", loadGS(t, out.Bytes()).Spec); err != nil || got["K"] != "v" {
		t.Fatalf("other recipient after rekey: %v %v", got, err)
	}
}
