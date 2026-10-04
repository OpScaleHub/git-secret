package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// sealForUnseal seals {DB_PASSWORD, NOTE} in operator home A to A and a
// second ("recovery") identity B, writes the manifest, and returns its path
// plus both homes and fingerprints.
func sealForUnseal(t *testing.T) (path, homeA, homeB, fprA, fprB string) {
	t.Helper()
	homeA = shortTempDir(t)
	fprA = genTestKey(t, homeA)
	homeB = shortTempDir(t)
	fprB = genTestKey(t, homeB)
	importPublicKeyCLI(t, homeA, exportPublicKeyCLI(t, homeB, fprB))

	t.Setenv("GNUPGHOME", homeA)
	var out, errb bytes.Buffer
	if code := run([]string{"seal", "--namespace", "prod", "--name", "db",
		"--recipient", fprA, "--recipient", fprB, "--no-provenance",
		"--from-literal", "DB_PASSWORD=it's s3cret", "--from-literal", "NOTE=line1\nline2",
	}, &out, &errb); code != exitOK {
		t.Fatalf("seal = %d: %s", code, errb.String())
	}
	path = t.TempDir() + "/db.yaml"
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, homeA, homeB, fprA, fprB
}

// TestUnseal_RecoveryKeyReadsValuesOffline is disaster recovery without a
// cluster: only the manifest and the *other* recipient's private key exist.
func TestUnseal_RecoveryKeyReadsValuesOffline(t *testing.T) {
	path, _, homeB, _, _ := sealForUnseal(t)
	t.Setenv("GNUPGHOME", homeB)

	var out, errb bytes.Buffer
	if code := run([]string{"unseal", "-f", path}, &out, &errb); code != exitOK {
		t.Fatalf("unseal = %d: %s", code, errb.String())
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("json output: %v\n%s", err, out.String())
	}
	if got["DB_PASSWORD"] != "it's s3cret" || got["NOTE"] != "line1\nline2" {
		t.Fatalf("values = %#v", got)
	}

	out.Reset()
	run([]string{"unseal", "-f", path, "--format", "env"}, &out, &errb)
	if want := "DB_PASSWORD='it'\\''s s3cret'\nNOTE='line1\nline2'\n"; out.String() != want {
		t.Errorf("env output = %q, want %q", out.String(), want)
	}

	out.Reset()
	run([]string{"unseal", "-f", path, "--key", "DB_PASSWORD"}, &out, &errb)
	if out.String() != "it's s3cret" {
		t.Errorf("--key output = %q (must be raw, no trailing newline)", out.String())
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"unseal", "-f", path, "--key", "MISSING"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "DB_PASSWORD, NOTE") {
		t.Errorf("missing key: code %d, stderr %q", code, errb.String())
	}
}

// TestUnseal_NonRecipientGetsAnActionableError: a keyring holding none of
// the recipients' secret keys must be told whose key is needed, not shown
// gpg's bare "No secret key" -- and must print nothing to stdout.
func TestUnseal_NonRecipientGetsAnActionableError(t *testing.T) {
	path, _, _, fprA, fprB := sealForUnseal(t)
	outsider := shortTempDir(t)
	genTestKey(t, outsider)
	t.Setenv("GNUPGHOME", outsider)

	var out, errb bytes.Buffer
	if code := run([]string{"unseal", "-f", path}, &out, &errb); code != exitError {
		t.Fatalf("unseal as outsider = %d, want %d", code, exitError)
	}
	if out.Len() != 0 {
		t.Fatalf("printed to stdout on failure: %q", out.String())
	}
	msg := errb.String()
	for _, want := range []string{"none of the secret keys", fprA, fprB} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

func TestUnseal_Usage(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{{"unseal"}, {"unseal", "-f", "x", "--format", "xml"}} {
		if code := run(args, &out, &errb); code != exitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
}
