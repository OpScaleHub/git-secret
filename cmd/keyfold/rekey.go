package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/OpScaleHub/keyfold/api/v1alpha1"
	"github.com/OpScaleHub/keyfold/internal/sealer"
)

const rekeyHelp = `keyfold rekey - re-encrypt every value under a fresh content key

  keyfold rekey -f FILE [--keyring SRC] > FILE.new

Unwraps the current content key (you must hold one recipient's private
key), generates a new one, re-encrypts every value under it, and wraps it
to the object's current spec.recipients (whose public keys must be in your
keyring). Values are unchanged; every ciphertext changes.

Use it to lock out a recipient who may have kept the old content key --
e.g. after 'recipients remove' of someone who already unwrapped it. It does
not protect values they have already read: for that, rotate the secret at
its source and 'keyfold set' the new value. See
docs/security/recipient-lifecycle.md.
`

const setHelp = `keyfold set - change or add one value

  keyfold set KEY -f FILE [--value-file PATH] [--keyring SRC] > FILE.new
  printf %s "$NEW" | keyfold set KEY -f FILE > FILE.new

Decrypts the object (you must hold one recipient's private key), sets KEY
to the new value (read from stdin, or --value-file), and re-seals every
value under a fresh content key wrapped to the current spec.recipients --
so you never re-enter the values you did not change. The value is never
taken from the command line, where shell history would keep it.
`

func runRekey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keyfold rekey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", "", "GitSecret manifest (- for stdin)")
	keyringSrc := fs.String("keyring", "", "keyring whose embedded publicKeys are used for wrapping (never imported)")
	if err := fs.Parse(args); err != nil || *file == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, rekeyHelp)
		return exitUsage
	}
	if cleanup, code := keyringForRun(*keyringSrc, stderr); code != exitOK {
		return code
	} else {
		defer cleanup()
	}
	gs, data, code := openForReseal(*file, stderr)
	if code != exitOK {
		return code
	}
	return reseal(gs, data, nil, stdout, stderr)
}

func runSet(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		io.WriteString(stderr, setHelp)
		return exitUsage
	}
	key := args[0]
	fs := flag.NewFlagSet("keyfold set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", "", "GitSecret manifest")
	valueFile := fs.String("value-file", "", "read the new value from this file instead of stdin")
	noProvenance := fs.Bool("no-provenance", false, "drop the source-revision/source-repo annotations instead of re-stamping them")
	keyringSrc := fs.String("keyring", "", "keyring whose embedded publicKeys are used for wrapping (never imported)")
	if err := fs.Parse(args[1:]); err != nil || *file == "" || *file == "-" || fs.NArg() != 0 {
		if *file == "-" {
			fmt.Fprintln(stderr, "error: set reads the new value from stdin, so -f must name a file")
		}
		io.WriteString(stderr, setHelp)
		return exitUsage
	}

	var raw []byte
	var err error
	if *valueFile != "" {
		raw, err = os.ReadFile(*valueFile)
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintln(stderr, "error: read new value:", err)
		return exitError
	}

	if cleanup, code := keyringForRun(*keyringSrc, stderr); code != exitOK {
		return code
	} else {
		defer cleanup()
	}
	gs, data, code := openForReseal(*file, stderr)
	if code != exitOK {
		return code
	}
	data[key] = string(raw)
	return reseal(gs, data, &provenanceRestamp{stamp: !*noProvenance}, stdout, stderr)
}

// provenanceRestamp controls the source-revision/source-repo annotations
// on a re-sealed object. nil keeps them (rekey: the plaintext is
// unchanged); otherwise the old stamp no longer describes the plaintext and
// is dropped, and a fresh one is added when stamp is set.
type provenanceRestamp struct{ stamp bool }

// openForReseal reads a GitSecret and decrypts it with the local keyring.
func openForReseal(file string, stderr io.Writer) (*v1alpha1.GitSecret, map[string]string, int) {
	gs, err := readGitSecret(file)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return nil, nil, exitError
	}
	if gs.Namespace == "" || gs.Name == "" {
		fmt.Fprintf(stderr, "error: %s has no metadata.namespace/name\n", file)
		return nil, nil, exitError
	}
	if len(gs.Spec.Recipients) == 0 {
		fmt.Fprintf(stderr, "error: %s lists no spec.recipients, so there is no recipient set to rewrap to -- re-seal it with 'keyfold seal --recipient ...' instead\n", file)
		return nil, nil, exitError
	}
	data, err := sealer.Unseal(gs.Namespace, gs.Name, gs.Spec)
	if err != nil {
		fmt.Fprintln(stderr, "error:", explainUnwrapError(err, gs))
		return nil, nil, exitError
	}
	return gs, data, exitOK
}

// reseal seals data under a fresh content key to gs's current recipients,
// keeping the target, roles and other annotations, and prints the manifest.
func reseal(gs *v1alpha1.GitSecret, data map[string]string, prov *provenanceRestamp, stdout, stderr io.Writer) int {
	spec, err := sealer.Seal(gs.Namespace, gs.Name, data, gs.Spec.Recipients)
	if err != nil {
		fmt.Fprintln(stderr, "error:", explainWrapError(err))
		return exitError
	}
	spec.Target = gs.Spec.Target
	gs.Spec = spec

	if prov != nil {
		for _, k := range []string{v1alpha1.SourceRevisionAnnotation, v1alpha1.SourceRepoAnnotation} {
			delete(gs.Annotations, k)
			delete(gs.Annotations, v1alpha1.LegacyAnnotationKey(k))
		}
		if len(gs.Annotations) == 0 {
			gs.Annotations = nil
		}
	}
	if prov != nil && prov.stamp {
		if rev, repo := gitProvenance(); rev != "" || repo != "" {
			if gs.Annotations == nil {
				gs.Annotations = map[string]string{}
			}
			if rev != "" {
				gs.Annotations[v1alpha1.SourceRevisionAnnotation] = rev
			}
			if repo != "" {
				gs.Annotations[v1alpha1.SourceRepoAnnotation] = repo
			}
		}
	}
	gs.Status = v1alpha1.GitSecretStatus{}

	out, err := marshalManifest(gs)
	if err != nil {
		fmt.Fprintln(stderr, "error: marshal manifest:", err)
		return exitError
	}
	stdout.Write(out)
	return exitOK
}

// explainWrapError turns gpg's "No public key" into which recipient's
// public key is missing from the local keyring.
func explainWrapError(err error) error {
	if !strings.Contains(err.Error(), "No public key") {
		return err
	}
	return fmt.Errorf("%w -- wrapping to the object's recipients needs every one of their public keys: pass --keyring with a keyring file whose entries carry publicKey, or gpg --import them (see docs/architecture/keyring.md)", err)
}

// keyringForRun makes --keyring's embedded public keys available for this
// run (see useKeyringPublicKeys); an empty src is a no-op.
func keyringForRun(src string, stderr io.Writer) (func(), int) {
	if src == "" {
		return func() {}, exitOK
	}
	cleanup, err := useKeyringPublicKeys(src)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return nil, exitError
	}
	return cleanup, exitOK
}
