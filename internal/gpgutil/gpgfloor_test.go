package gpgutil

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

// TestGPGSuiteFloor is the guard for #78 item 6. The GPG-dependent suites
// across this repo all `t.Skip` when gpg is missing, on Windows, or when
// unattended key generation fails -- so a broken gpg/gpg-agent on a runner
// silently turns every real assertion into a skip while CI still reports
// green.
//
// When REQUIRE_GPG_TESTS=1 (set by CI on the Linux matrix leg only), this
// test refuses to skip: if gpg is not actually usable end-to-end here, it
// fails, and the "GPG suite didn't really run" condition becomes visible.
// Everywhere else it is a normal skip.
func TestGPGSuiteFloor(t *testing.T) {
	required := os.Getenv("REQUIRE_GPG_TESTS") == "1"

	fail := func(format string, args ...any) {
		if required {
			t.Fatalf("REQUIRE_GPG_TESTS=1 but "+format, args...)
		}
		t.Skipf(format, args...)
	}

	if !Available() {
		fail("gpg binary not found on PATH")
	}

	home := shortTempDir(t)
	t.Setenv("GNUPGHOME", home)
	cmd := exec.Command(Binary, "--batch", "--passphrase", "", "--quick-generate-key",
		"GPG Floor <gpg-floor@example.invalid>", "default", "default", "never")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fail("gpg cannot generate a key unattended: %v: %s", err, stderr.String())
	}

	keys, err := ListSecretKeys()
	if err != nil || len(keys) == 0 {
		fail("gpg generated a key but it could not be listed back: err=%v keys=%d", err, len(keys))
	}
}
