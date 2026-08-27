package sealer

import (
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
// they cannot decrypt any *future* version of the object. (They can still read
// whatever they already pulled from git history -- that is the compromise
// case, scenario E, not this one.)
func TestRecovery_OperatorLeaves_RewrapRevokesFutureAccess(t *testing.T) {
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

	// Alice cannot open the rewrapped object.
	t.Setenv("GNUPGHOME", aliceHome)
	if _, err := Unseal("prod", "app-secrets", rewrapped); err == nil {
		t.Fatal("Alice could still decrypt after being dropped from the recipient list")
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
