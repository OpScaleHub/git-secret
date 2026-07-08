package cli

import (
	"strings"
	"testing"

	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

func testKeys() []gpgutil.SecretKey {
	return []gpgutil.SecretKey{
		{Fingerprint: "1111111111111111111111111111111111111111", UserIDs: []string{"Alice <alice@example.com>"}},
		{Fingerprint: "2222222222222222222222222222222222222222", UserIDs: []string{"Bob <bob@example.com>"}},
	}
}

func TestPickGPGRecipientValidSelection(t *testing.T) {
	var out strings.Builder
	got, err := PickGPGRecipient(strings.NewReader("2\n"), &out, testKeys())
	if err != nil {
		t.Fatalf("PickGPGRecipient: %v", err)
	}
	if got != "2222222222222222222222222222222222222222" {
		t.Fatalf("got %q, want Bob's fingerprint", got)
	}
	if !strings.Contains(out.String(), "Alice <alice@example.com>") || !strings.Contains(out.String(), "Bob <bob@example.com>") {
		t.Fatalf("menu output missing expected entries: %q", out.String())
	}
}

func TestPickGPGRecipientNoKeys(t *testing.T) {
	var out strings.Builder
	if _, err := PickGPGRecipient(strings.NewReader("1\n"), &out, nil); err == nil {
		t.Fatalf("expected error with no keys available")
	}
}

func TestPickGPGRecipientOutOfRange(t *testing.T) {
	var out strings.Builder
	if _, err := PickGPGRecipient(strings.NewReader("99\n"), &out, testKeys()); err == nil {
		t.Fatalf("expected error for out-of-range selection")
	}
}

func TestPickGPGRecipientNonNumeric(t *testing.T) {
	var out strings.Builder
	if _, err := PickGPGRecipient(strings.NewReader("banana\n"), &out, testKeys()); err == nil {
		t.Fatalf("expected error for non-numeric input")
	}
}

func TestPickGPGRecipientNoInput(t *testing.T) {
	var out strings.Builder
	if _, err := PickGPGRecipient(strings.NewReader(""), &out, testKeys()); err == nil {
		t.Fatalf("expected error when input is closed with nothing read")
	}
}

func TestPickGPGRecipientMissingUID(t *testing.T) {
	var out strings.Builder
	keys := []gpgutil.SecretKey{{Fingerprint: "3333333333333333333333333333333333333333"}}
	got, err := PickGPGRecipient(strings.NewReader("1\n"), &out, keys)
	if err != nil {
		t.Fatalf("PickGPGRecipient: %v", err)
	}
	if got != keys[0].Fingerprint {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(out.String(), "(no user ID)") {
		t.Fatalf("expected placeholder for missing UID: %q", out.String())
	}
}
