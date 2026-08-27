package sealer

import (
	"testing"
)

func TestSeal_PopulatesSortedRecipients(t *testing.T) {
	homeA := shortTempDir(t)
	fprA := genTestKey(t, homeA)
	homeB := shortTempDir(t)
	fprB := genTestKey(t, homeB)

	// Seal (in A's keyring) needs B's public key too.
	importPublicKey(t, homeA, exportPublicKey(t, homeB, fprB))
	t.Setenv("GNUPGHOME", homeA)

	// Pass out of order; spec.Recipients must come back sorted and stable.
	hi, lo := fprA, fprB
	if hi < lo {
		hi, lo = lo, hi
	}
	spec, err := Seal("prod", "app", map[string]string{"K": "v"}, []string{hi, lo})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(spec.Recipients) != 2 || spec.Recipients[0] != lo || spec.Recipients[1] != hi {
		t.Fatalf("spec.Recipients = %v, want sorted [%s %s]", spec.Recipients, lo, hi)
	}
	if err := VerifyRecipients(spec); err != nil {
		t.Fatalf("VerifyRecipients on fresh Seal output: %v", err)
	}
}

func TestRewrap_ReplacesRecipients(t *testing.T) {
	homeA := shortTempDir(t)
	fprA := genTestKey(t, homeA)
	homeB := shortTempDir(t)
	fprB := genTestKey(t, homeB)

	importPublicKey(t, homeA, exportPublicKey(t, homeB, fprB))
	t.Setenv("GNUPGHOME", homeA)

	spec, err := Seal("prod", "app", map[string]string{"K": "v"}, []string{fprA})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(spec.Recipients) != 1 {
		t.Fatalf("initial Recipients = %v", spec.Recipients)
	}

	rewrapped, err := Rewrap(spec, []string{fprA, fprB})
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	if len(rewrapped.Recipients) != 2 {
		t.Fatalf("rewrapped Recipients = %v, want 2", rewrapped.Recipients)
	}
	if err := VerifyRecipients(rewrapped); err != nil {
		t.Fatalf("VerifyRecipients after Rewrap: %v", err)
	}
}

func TestVerifyRecipients_DetectsDrift(t *testing.T) {
	home := shortTempDir(t)
	fpr := genTestKey(t, home)
	t.Setenv("GNUPGHOME", home)

	spec, err := Seal("prod", "app", map[string]string{"K": "v"}, []string{fpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Empty Recipients -> nothing claimed, VerifyRecipients is a no-op.
	noClaim := spec
	noClaim.Recipients = nil
	if err := VerifyRecipients(noClaim); err != nil {
		t.Fatalf("VerifyRecipients with no claim should pass: %v", err)
	}

	// Claim two recipients when the blob only has one.
	drifted := spec
	drifted.Recipients = []string{fpr, "0000000000000000000000000000000000000000"}
	if err := VerifyRecipients(drifted); err == nil {
		t.Fatal("VerifyRecipients did not catch a recipient-count mismatch")
	}

	// A non-fingerprint entry is rejected outright.
	bad := spec
	bad.Recipients = []string{"DEADBEEF"}
	if err := VerifyRecipients(bad); err == nil {
		t.Fatal("VerifyRecipients accepted a short key ID in spec.recipients")
	}
}
