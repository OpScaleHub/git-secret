package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

// sealManifest runs the seal path and returns the manifest bytes + path.
func sealManifest(t *testing.T, gnupgHome, fpr string) (string, []byte) {
	t.Helper()
	t.Setenv("GNUPGHOME", gnupgHome)
	var out, errb bytes.Buffer
	if code := run([]string{"--namespace", "ns", "--name", "obj", "--recipient", fpr, "--from-literal", "K=v"}, &out, &errb); code != exitOK {
		t.Fatalf("seal run() = %d: %s", code, errb.String())
	}
	path := t.TempDir() + "/gitsecret.yaml"
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, out.Bytes()
}

func TestRecipients_ListAndAddAndRemove(t *testing.T) {
	homeA := shortTempDir(t)
	fprA := genTestKey(t, homeA)
	path, _ := sealManifest(t, homeA, fprA)

	// list: one human recipient.
	var lsOut, lsErr bytes.Buffer
	if code := run([]string{"recipients", "list", "-f", path}, &lsOut, &lsErr); code != exitOK {
		t.Fatalf("list = %d: %s", code, lsErr.String())
	}
	if !strings.Contains(lsOut.String(), fprA) || !strings.Contains(lsOut.String(), "human") {
		t.Fatalf("list output = %q", lsOut.String())
	}

	// add B as a recovery recipient.
	homeB := shortTempDir(t)
	fprB := genTestKey(t, homeB)
	importPublicKeyCLI(t, homeA, exportPublicKeyCLI(t, homeB, fprB))
	t.Setenv("GNUPGHOME", homeA)

	var addOut, addErr bytes.Buffer
	if code := run([]string{"recipients", "add", fprB, "-f", path, "--role", "recovery"}, &addOut, &addErr); code != exitOK {
		t.Fatalf("add = %d: %s", code, addErr.String())
	}
	var gs v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(addOut.Bytes(), &gs); err != nil {
		t.Fatal(err)
	}
	if len(gs.Spec.Recipients) != 2 {
		t.Fatalf("after add, recipients = %v", gs.Spec.Recipients)
	}
	if v1alpha1.ParseRecipientRoles(gs.Annotations)[strings.ToUpper(fprB)] != v1alpha1.RoleRecovery {
		t.Fatalf("B role not recorded: %v", gs.Annotations)
	}
	// B can now decrypt.
	t.Setenv("GNUPGHOME", homeB)
	if _, err := sealer.Unseal("ns", "obj", gs.Spec); err != nil {
		t.Fatalf("B cannot decrypt after add: %v", err)
	}

	// Write the 2-recipient manifest back, then removing the recovery one
	// (B) must be refused without --force.
	if err := os.WriteFile(path, addOut.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", homeA)
	var rmOut, rmErr bytes.Buffer
	if code := run([]string{"recipients", "remove", fprB, "-f", path}, &rmOut, &rmErr); code == exitOK {
		t.Fatalf("remove of last recovery recipient should have failed; got ok, stderr=%s", rmErr.String())
	}
	if !strings.Contains(rmErr.String(), "recovery") {
		t.Fatalf("unexpected refusal message: %s", rmErr.String())
	}

	// --force lets it through.
	var frOut, frErr bytes.Buffer
	if code := run([]string{"recipients", "remove", fprB, "-f", path, "--force"}, &frOut, &frErr); code != exitOK {
		t.Fatalf("forced remove = %d: %s", code, frErr.String())
	}
	var after v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(frOut.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Spec.Recipients) != 1 || after.Spec.Recipients[0] != fprA {
		t.Fatalf("after forced remove, recipients = %v", after.Spec.Recipients)
	}
	if _, ok := after.Annotations[v1alpha1.RecipientRolesAnnotation]; ok {
		t.Fatalf("roles annotation should be gone, got %v", after.Annotations)
	}
}

func TestRecipients_RemoveLastIsRefused(t *testing.T) {
	home := shortTempDir(t)
	fpr := genTestKey(t, home)
	path, _ := sealManifest(t, home, fpr)

	var out, errb bytes.Buffer
	if code := run([]string{"recipients", "remove", fpr, "-f", path}, &out, &errb); code == exitOK {
		t.Fatal("removing the only recipient should be refused")
	}
	if !strings.Contains(errb.String(), "last recipient") {
		t.Fatalf("unexpected message: %s", errb.String())
	}
}
