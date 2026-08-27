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

func TestRun_KeyringResolvesRecipientsAndRoles(t *testing.T) {
	ctrlHome := shortTempDir(t)
	ctrlFpr := genTestKey(t, ctrlHome)
	recHome := shortTempDir(t)
	recFpr := genTestKey(t, recHome)

	// Seal runs in the controller's keyring; it needs the recovery pubkey.
	importPublicKeyCLI(t, ctrlHome, exportPublicKeyCLI(t, recHome, recFpr))
	t.Setenv("GNUPGHOME", ctrlHome)

	keyring := "recipients:\n" +
		"  - fingerprint: " + ctrlFpr + "\n" +
		"    role: controller\n" +
		"  - fingerprint: " + recFpr + "\n" +
		"    role: recovery\n"
	krPath := t.TempDir() + "/keyring.yaml"
	if err := os.WriteFile(krPath, []byte(keyring), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := run([]string{
		"--namespace", "ns", "--name", "obj",
		"--keyring", krPath,
		"--from-literal", "K=v",
	}, &out, &errb)
	if code != exitOK {
		t.Fatalf("run() = %d: %s", code, errb.String())
	}

	var gs v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(out.Bytes(), &gs); err != nil {
		t.Fatal(err)
	}
	if len(gs.Spec.Recipients) != 2 {
		t.Fatalf("recipients = %v, want 2 from the keyring", gs.Spec.Recipients)
	}
	roles := v1alpha1.ParseRecipientRoles(gs.Annotations)
	if roles[upperFP(ctrlFpr)] != v1alpha1.RoleController || roles[upperFP(recFpr)] != v1alpha1.RoleRecovery {
		t.Fatalf("roles not recorded from keyring: %v", gs.Annotations)
	}

	// Both identities can decrypt.
	for _, home := range []string{ctrlHome, recHome} {
		t.Setenv("GNUPGHOME", home)
		if _, err := sealer.Unseal("ns", "obj", gs.Spec); err != nil {
			t.Fatalf("unseal with %s failed: %v", home, err)
		}
	}
}

func TestRun_KeyringRejectsBadFingerprint(t *testing.T) {
	krPath := t.TempDir() + "/keyring.yaml"
	if err := os.WriteFile(krPath, []byte("recipients:\n  - fingerprint: NOTAFINGERPRINT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"--namespace", "ns", "--name", "o", "--keyring", krPath, "--from-literal", "K=v"}, &out, &errb)
	if code == exitOK {
		t.Fatal("expected failure on a malformed keyring fingerprint")
	}
	if !strings.Contains(errb.String(), "fingerprint") {
		t.Fatalf("unexpected error: %s", errb.String())
	}
}
