package cli

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/OpScaleHub/git-secret/internal/gpgutil"
)

// PickGPGRecipient prints a numbered menu of keys to stdout and reads a
// selection from stdin, returning the chosen key's fingerprint. It's a
// pure function of its inputs (no direct os.Stdin/os.Stdout access) so
// it's unit-testable without a real terminal; main.go is responsible for
// deciding whether a session is interactive before calling this.
func PickGPGRecipient(stdin io.Reader, stdout io.Writer, keys []gpgutil.SecretKey) (string, error) {
	if len(keys) == 0 {
		return "", fmt.Errorf("no local GPG keys found — generate one with `gpg --full-generate-key`, or pass the recipient explicitly")
	}
	fmt.Fprintln(stdout, "Select a GPG key to encrypt the repo key to:")
	for i, k := range keys {
		uid := "(no user ID)"
		if len(k.UserIDs) > 0 {
			uid = k.UserIDs[0]
		}
		fmt.Fprintf(stdout, "  [%d] %s  %s\n", i+1, k.Fingerprint, uid)
	}
	fmt.Fprint(stdout, "Enter a number: ")

	scanner := bufio.NewScanner(stdin)
	if !scanner.Scan() {
		return "", fmt.Errorf("no selection read (input closed)")
	}
	text := strings.TrimSpace(scanner.Text())
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 || n > len(keys) {
		return "", fmt.Errorf("invalid selection %q (expected a number from 1 to %d)", text, len(keys))
	}
	return keys[n-1].Fingerprint, nil
}
