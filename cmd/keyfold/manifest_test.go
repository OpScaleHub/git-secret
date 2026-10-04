package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSeal_ManifestHasNoEmptyStatusOrTarget(t *testing.T) {
	home := shortTempDir(t)
	fpr := genTestKey(t, home)
	t.Setenv("GNUPGHOME", home)

	var out, errb bytes.Buffer
	if code := run([]string{"seal", "--namespace", "n", "--name", "x", "--recipient", fpr, "--no-provenance", "--from-literal", "K=v"}, &out, &errb); code != exitOK {
		t.Fatalf("seal: %s", errb.String())
	}
	for _, noise := range []string{"status:", "target:"} {
		if strings.Contains(out.String(), noise) {
			t.Errorf("sealed manifest carries an empty %q block:\n%s", noise, out.String())
		}
	}

	out.Reset()
	run([]string{"seal", "--namespace", "n", "--name", "x", "--recipient", fpr, "--no-provenance", "--target-name", "app-secret", "--from-literal", "K=v"}, &out, &errb)
	if !strings.Contains(out.String(), "target:\n    name: app-secret") {
		t.Errorf("a set target was dropped:\n%s", out.String())
	}
}
