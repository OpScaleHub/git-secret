package sealer

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// These tests are the executable form of docs/security/disaster-recovery.md:
// each one corresponds to a scenario row in that document and proves (or, for
// the compromise case, deliberately proves the *limit* of) what recovery the
// cryptography actually gives you. They run entirely on throwaway GPG keys in
// isolated GNUPGHOMEs -- no cluster required, because every recovery guarantee
// this project makes is a property of the seal/rewrap envelope, not of
// Kubernetes.

func exportSecretKey(t *testing.T, gnupgHome, fpr string) []byte {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--armor", "--export-secret-keys", fpr)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("export secret key: %v", err)
	}
	return out
}

func importSecretKey(t *testing.T, gnupgHome string, armored []byte) {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--import")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	cmd.Stdin = strings.NewReader(string(armored))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("import secret key: %v\n%s", err, out)
	}
}

// Scenario A/B -- controller pod, or the entire cluster, is destroyed.
// A fresh controller with the same GPG identity, handed the same GitSecret
// object, reproduces the identical Secret. Modeled here as: export the
// controller's private key, throw the keyring away, stand up a brand-new
// keyring, re-import, Unseal.
func TestRecovery_ClusterRebuild_SameKeyReproducesData(t *testing.T) {
	oldHome := shortTempDir(t)
	fpr := genTestKey(t, oldHome)
	t.Setenv("GNUPGHOME", oldHome)

	data := map[string]string{"API_KEY": "s3cr3t", "DB_URL": "postgres://x"}
	spec, err := Seal("prod", "app-secrets", data, []string{fpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// The old cluster (and its keyring) is gone. Only two things survived:
	// the GitSecret manifest (spec) and a backup of the controller key.
	keyBackup := exportSecretKey(t, oldHome, fpr)
	os.RemoveAll(oldHome)

	newHome := shortTempDir(t)
	importSecretKey(t, newHome, keyBackup)
	t.Setenv("GNUPGHOME", newHome)

	got, err := Unseal("prod", "app-secrets", spec)
	if err != nil {
		t.Fatalf("fresh controller could not Unseal after rebuild: %v", err)
	}
	for k, want := range data {
		if got[k] != want {
			t.Errorf("key %q: got %q, want %q", k, got[k], want)
		}
	}
}

// Scenario C -- the controller's private key is lost (no backup, holder gone),
// but the GitSecret was also wrapped to a human operator. That operator
// rewraps to a fresh controller identity. No value is re-sealed; the new
// controller decrypts independently.
func TestRecovery_ControllerKeyLost_HumanRewrapsToNewController(t *testing.T) {
	humanHome := shortTempDir(t)
	humanFpr := genTestKey(t, humanHome)

	oldCtrlHome := shortTempDir(t)
	oldCtrlFpr := genTestKey(t, oldCtrlHome)

	// Seal (done by the human) needs both public keys present.
	importPublicKey(t, humanHome, exportPublicKey(t, oldCtrlHome, oldCtrlFpr))
	t.Setenv("GNUPGHOME", humanHome)
	spec, err := Seal("prod", "app-secrets", map[string]string{"K": "v"}, []string{humanFpr, oldCtrlFpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	originalData := spec.EncryptedData["K"]

	// The controller key is now unrecoverable. A new controller identity is
	// generated; the human (still a current recipient) rewraps to it.
	newCtrlHome := shortTempDir(t)
	newCtrlFpr := genTestKey(t, newCtrlHome)
	importPublicKey(t, humanHome, exportPublicKey(t, newCtrlHome, newCtrlFpr))

	t.Setenv("GNUPGHOME", humanHome)
	rewrapped, err := Rewrap(spec, []string{humanFpr, newCtrlFpr})
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	if rewrapped.EncryptedData["K"] != originalData {
		t.Fatal("Rewrap re-sealed a value; recovery must never touch encryptedData")
	}

	// The new controller, which never saw the original Seal, decrypts.
	t.Setenv("GNUPGHOME", newCtrlHome)
	got, err := Unseal("prod", "app-secrets", rewrapped)
	if err != nil || got["K"] != "v" {
		t.Fatalf("new controller cannot decrypt after rewrap: got=%v err=%v", got, err)
	}
}

// Scenario D -- an operator leaves. Rewrapping without their fingerprint means
// their key can no longer *unwrap the content key* from the rewrapped object.
//
// NOTE: this is not full cryptographic revocation. Rewrap keeps the same
// content key and never touches encryptedData (invariant #6), so an operator
// who already unwrapped that content key once can still open any value that has
// not since been *changed* -- a value change re-seals under a fresh key. Denying
// access to current, unchanged data is the compromise case, scenario E. They
// can also still read whatever they already pulled from git history.
func TestRecovery_OperatorLeaves_RewrapDropsKeyUnwrap(t *testing.T) {
	aliceHome := shortTempDir(t)
	aliceFpr := genTestKey(t, aliceHome)
	bobHome := shortTempDir(t)
	bobFpr := genTestKey(t, bobHome)

	importPublicKey(t, aliceHome, exportPublicKey(t, bobHome, bobFpr))
	t.Setenv("GNUPGHOME", aliceHome)
	spec, err := Seal("prod", "app-secrets", map[string]string{"K": "v"}, []string{aliceFpr, bobFpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Bob rewraps, dropping Alice.
	t.Setenv("GNUPGHOME", bobHome)
	rewrapped, err := Rewrap(spec, []string{bobFpr})
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	// Bob still works.
	if got, err := Unseal("prod", "app-secrets", rewrapped); err != nil || got["K"] != "v" {
		t.Fatalf("Bob lost access after his own rewrap: got=%v err=%v", got, err)
	}

	// Alice's key can no longer unwrap the content key from the rewrapped
	// object (Unseal goes through gpg --decrypt on encryptedKey, which is now
	// wrapped only to Bob). This is the unwrap path only -- see the note on
	// this function about residual access to unchanged values via a cached
	// content key.
	t.Setenv("GNUPGHOME", aliceHome)
	if _, err := Unseal("prod", "app-secrets", rewrapped); err == nil {
		t.Fatal("Alice's key still unwrapped the rewrapped encryptedKey after being dropped")
	}
}

// Scenario E -- a recipient key is COMPROMISED. This test documents the limit
// of the design: rewrap alone is NOT sufficient, because the pre-rewrap object
// (which lives forever in git history) stays readable by the compromised key.
// Only a fresh content key + full re-seal produces an object the compromised
// key cannot open.
func TestRecovery_KeyCompromise_RewrapAloneIsInsufficient(t *testing.T) {
	ownerHome := shortTempDir(t)
	ownerFpr := genTestKey(t, ownerHome)
	attackerHome := shortTempDir(t)
	attackerFpr := genTestKey(t, attackerHome)

	// The attacker's key was a legitimate recipient before the compromise
	// was discovered.
	importPublicKey(t, ownerHome, exportPublicKey(t, attackerHome, attackerFpr))
	t.Setenv("GNUPGHOME", ownerHome)
	original, err := Seal("prod", "app-secrets", map[string]string{"K": "v"}, []string{ownerFpr, attackerFpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Response step 1: rewrap to drop the attacker.
	rewrapped, err := Rewrap(original, []string{ownerFpr})
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	// The attacker CANNOT open the rewrapped object...
	t.Setenv("GNUPGHOME", attackerHome)
	if _, err := Unseal("prod", "app-secrets", rewrapped); err == nil {
		t.Fatal("attacker opened the rewrapped object; expected failure")
	}
	// ...but they CAN still open the original, which is what git history holds.
	// This is the property operators must understand, so assert it explicitly.
	if got, err := Unseal("prod", "app-secrets", original); err != nil || got["K"] != "v" {
		t.Fatalf("expected the compromised key to still open the pre-rewrap object "+
			"(historical exposure is real): got=%v err=%v", got, err)
	}

	// Response step 2: full re-seal under a fresh content key. Only now is
	// there an object version the compromised key has never been able to open.
	t.Setenv("GNUPGHOME", ownerHome)
	resealed, err := Seal("prod", "app-secrets", map[string]string{"K": "v"}, []string{ownerFpr})
	if err != nil {
		t.Fatalf("re-Seal: %v", err)
	}
	if resealed.EncryptedData["K"] == original.EncryptedData["K"] {
		t.Fatal("re-Seal produced identical ciphertext; the content key was not rotated")
	}
	t.Setenv("GNUPGHOME", attackerHome)
	if _, err := Unseal("prod", "app-secrets", resealed); err == nil {
		t.Fatal("attacker opened the re-sealed object; content-key rotation did not take effect")
	}
}

// The "no plaintext in error output" invariant (threat-model.md I3): a
// corrupted or tampered envelope must fail without the decrypt path ever
// echoing a secret value into the error it returns (which the controller
// copies verbatim into GitSecret .status).
func TestUnseal_ErrorDoesNotLeakPlaintext(t *testing.T) {
	gnupgHome := shortTempDir(t)
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	const secretValue = "correct-horse-battery-staple-unique-marker"
	spec, err := Seal("prod", "app-secrets", map[string]string{"K": secretValue}, []string{fpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flip a byte in the middle of the (decoded) envelope so AEAD auth fails.
	raw, _ := base64.StdEncoding.DecodeString(spec.EncryptedData["K"])
	raw[len(raw)/2] ^= 0xff
	spec.EncryptedData["K"] = base64.StdEncoding.EncodeToString(raw)

	_, err = Unseal("prod", "app-secrets", spec)
	if err == nil {
		t.Fatal("Unseal accepted a tampered envelope")
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("error message leaked the plaintext value: %v", err)
	}
}

func TestUnseal_RejectsTooManyEntries(t *testing.T) {
	gnupgHome := shortTempDir(t)
	fpr := genTestKey(t, gnupgHome)
	t.Setenv("GNUPGHOME", gnupgHome)

	spec, err := Seal("prod", "app-secrets", map[string]string{"K": "v"}, []string{fpr})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Pad EncryptedData past the limit with junk entries.
	for i := 0; i <= MaxEntries; i++ {
		spec.EncryptedData[fmt.Sprintf("junk-%d", i)] = "junk"
	}
	if _, err := Unseal("prod", "app-secrets", spec); err == nil {
		t.Fatal("Unseal processed an over-limit EncryptedData map")
	}
}
