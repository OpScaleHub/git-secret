package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/OpScaleHub/keyfold/api/v1alpha1"
	"github.com/OpScaleHub/keyfold/internal/sealer"
)

const unsealHelp = `keyfold unseal - read a GitSecret's values without a cluster

  keyfold unseal -f FILE [--key KEY] [--format json|env] [--show]

Unwraps the content key with a GPG secret key in your keyring (any one of
the object's recipients -- typically the offline recovery key) and prints
the decrypted values. This is disaster recovery without Kubernetes: the
encrypted manifest plus one recipient key is all it needs.

  -f FILE         the GitSecret manifest (- for stdin)
  --key KEY       print only this value, raw, with no trailing newline
  --format FMT    json (default; lossless) or env (KEY='value' lines)
  --show          allow printing to a terminal

Plaintext goes to stdout only -- never to a file this command opens. By
default it refuses to print to a terminal, so values don't end up in
scrollback or a screen share; pipe it (| kubectl create secret ...,
| jq ...) or pass --show.
`

func runUnseal(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keyfold unseal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", "", "GitSecret manifest (- for stdin)")
	only := fs.String("key", "", "print only this value, raw")
	format := fs.String("format", "json", "json or env")
	show := fs.Bool("show", false, "allow printing to a terminal")
	if err := fs.Parse(args); err != nil {
		fmt.Fprint(stderr, unsealHelp)
		return exitUsage
	}
	if *file == "" || (*format != "json" && *format != "env") {
		fmt.Fprint(stderr, unsealHelp)
		return exitUsage
	}
	if isTerminal(stdout) && !*show {
		fmt.Fprintln(stderr, "error: refusing to print secret values to a terminal; pipe the output or pass --show")
		return exitUsage
	}

	gs, err := readGitSecret(*file)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if gs.Namespace == "" || gs.Name == "" {
		fmt.Fprintf(stderr, "error: %s has no metadata.namespace/name -- both are bound into every value's ciphertext, so they are needed to decrypt\n", *file)
		return exitError
	}
	data, err := sealer.Unseal(gs.Namespace, gs.Name, gs.Spec)
	if err != nil {
		fmt.Fprintln(stderr, "error:", explainUnwrapError(err, gs))
		return exitError
	}

	if *only != "" {
		v, ok := data[*only]
		if !ok {
			fmt.Fprintf(stderr, "error: %s/%s has no key %q (keys: %s)\n", gs.Namespace, gs.Name, *only, strings.Join(sortedKeys(data), ", "))
			return exitError
		}
		fmt.Fprint(stdout, v)
		return exitOK
	}
	switch *format {
	case "env":
		for _, k := range sortedKeys(data) {
			fmt.Fprintf(stdout, "%s=%s\n", k, shellQuote(data[k]))
		}
	default:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
	}
	return exitOK
}

// explainUnwrapError turns gpg's "No secret key" into what it means for
// this object: none of its recipients' secret keys is in this keyring.
func explainUnwrapError(err error, gs *v1alpha1.GitSecret) error {
	if !strings.Contains(err.Error(), "No secret key") {
		return err
	}
	who := "spec.recipients is empty"
	if len(gs.Spec.Recipients) > 0 {
		roles := v1alpha1.ParseRecipientRoles(gs.Annotations)
		var parts []string
		for _, fp := range gs.Spec.Recipients {
			role := roles[strings.ToUpper(fp)]
			if role == "" {
				role = v1alpha1.RoleHuman
			}
			parts = append(parts, fmt.Sprintf("%s (%s)", fp, role))
		}
		who = "it is wrapped to: " + strings.Join(parts, ", ")
	}
	return fmt.Errorf("your GPG keyring holds none of the secret keys this object's content key is wrapped to -- %s. Run this where one of those private keys is available (GNUPGHOME, or a hardware token)", who)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// shellQuote single-quotes v for a POSIX shell / dotenv line.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
