// Command git-secret-seal produces a GitSecret manifest (api/v1alpha1)
// from plaintext values, GPG-wrapped to one or more recipients -- the
// "kubeseal" analog for the GitSecret CRD. See internal/sealer for the
// underlying cryptography and internal/controller for how the ciphertext
// this emits gets consumed.
//
// Nothing this command produces or reads ever touches disk in plaintext
// form beyond what the caller explicitly gave it (a literal, an env file,
// or an existing Secret manifest) -- the emitted manifest is ciphertext
// only.
package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

var version = "dev"

const helpText = `git-secret-seal - produce a GitSecret manifest from plaintext values

Usage:
  git-secret-seal --namespace NS --name NAME --recipient FPR [--recipient FPR ...] \
      [--from-literal KEY=VALUE ...] [--from-env-file FILE] [-f secret.yaml] \
      [--target-name NAME] [--target-type TYPE]

  -f/--from-secret-file FILE   Read an existing Secret manifest (data or
                                stringData) and seal its values. --namespace
                                and --name default to its metadata unless
                                given explicitly.
  --from-literal KEY=VALUE     Add one value. Repeatable.
  --from-env-file FILE         Add every KEY=VALUE line from FILE (# comments
                                and blank lines skipped).
  --namespace NS                Namespace the GitSecret (and by default its
                                target Secret) will live in. Required.
  --name NAME                   Name of the GitSecret object. Required.
  --recipient FPR               Full 40/64-hex GPG fingerprint to encrypt to.
                                Repeatable; at least one required. Passing
                                every current human + controller recipient
                                here, not just the controller's own key, is
                                what avoids sealed-secrets' single-keypair
                                DR weakness -- see docs/adr/0002.
  --target-name NAME             Name of the Secret the controller creates.
                                Defaults to --name.
  --target-type TYPE             Kubernetes Secret type. Defaults to Opaque.
  --version                      Show version information.

Output is a single GitSecret YAML manifest on stdout. Combine multiple
--from-literal values freely; combine -f with --from-literal to override or
add individual keys on top of what the Secret manifest already had.

Usage (rewrap -- add/remove a recipient without re-encrypting any value):
  git-secret-seal --rewrap gitsecret.yaml --recipient FPR [--recipient FPR ...]

  --rewrap FILE                  Path to an existing GitSecret manifest
                                (- for stdin). Re-encrypts its content key
                                to exactly the given --recipient list and
                                prints the updated manifest; encryptedData
                                is copied through byte-for-byte. Requires a
                                local GPG secret key that can already open
                                FILE's current encryptedKey -- i.e. run
                                this as one of the object's current
                                recipients, not an outsider. The given
                                --recipient list REPLACES the old one:
                                include everyone who should still be able
                                to decrypt, not just the one being added.

Exit codes: 0 ok, 1 error, 2 usage/key unavailable.
`

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("git-secret-seal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	namespace := fs.String("namespace", "", "namespace for the GitSecret and (by default) its target Secret")
	name := fs.String("name", "", "name of the GitSecret object")
	targetName := fs.String("target-name", "", "name of the target Secret (defaults to --name)")
	targetType := fs.String("target-type", "", "Kubernetes Secret type (defaults to Opaque)")
	fromSecretFile := fs.String("from-secret-file", "", "path to an existing Secret manifest to seal (- for stdin)")
	fromEnvFile := fs.String("from-env-file", "", "path to a KEY=VALUE file to seal")
	rewrapFile := fs.String("rewrap", "", "path to an existing GitSecret manifest to rewrap to a new --recipient list, without re-encrypting its values (- for stdin)")
	showVersion := fs.Bool("version", false, "print version and exit")
	var literals stringSlice
	var recipients stringSlice
	fs.Var(&literals, "from-literal", "KEY=VALUE to seal (repeatable)")
	fs.Var(&recipients, "recipient", "GPG fingerprint to encrypt to (repeatable)")
	fs.StringVar(fromSecretFile, "f", "", "shorthand for --from-secret-file")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stderr, helpText)
			return exitUsage
		}
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, "git-secret-seal", version)
		return exitOK
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, helpText)
		return exitUsage
	}

	if *rewrapFile != "" {
		return runRewrap(*rewrapFile, recipients, stdout, stderr)
	}

	data := map[string]string{}
	ns, nm := *namespace, *name

	if *fromSecretFile != "" {
		fileData, secNs, secName, err := readSecretFile(*fromSecretFile)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		for k, v := range fileData {
			data[k] = v
		}
		if ns == "" {
			ns = secNs
		}
		if nm == "" {
			nm = secName
		}
	}

	if *fromEnvFile != "" {
		envData, err := readEnvFile(*fromEnvFile)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		for k, v := range envData {
			data[k] = v
		}
	}

	for _, lit := range literals {
		k, v, ok := strings.Cut(lit, "=")
		if !ok {
			fmt.Fprintf(stderr, "error: --from-literal %q is not KEY=VALUE\n", lit)
			return exitUsage
		}
		data[k] = v
	}

	if ns == "" || nm == "" {
		fmt.Fprintln(stderr, "error: --namespace and --name are required (or must be derivable from -f's Secret metadata)")
		return exitUsage
	}
	if len(recipients) == 0 {
		fmt.Fprintln(stderr, "error: at least one --recipient is required")
		return exitUsage
	}
	if len(data) == 0 {
		fmt.Fprintln(stderr, "error: no values to seal (use --from-literal, --from-env-file, or -f)")
		return exitUsage
	}
	if !gpgutil.Available() {
		fmt.Fprintln(stderr, "error: gpg binary not found on PATH")
		return exitError
	}

	spec, err := sealer.Seal(ns, nm, data, recipients)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if *targetName != "" {
		spec.Target.Name = *targetName
	}
	if *targetType != "" {
		spec.Target.Type = corev1.SecretType(*targetType)
	}

	gs := v1alpha1.GitSecret{}
	gs.APIVersion = v1alpha1.GroupVersion.Group + "/" + v1alpha1.GroupVersion.Version
	gs.Kind = "GitSecret"
	gs.Name = nm
	gs.Namespace = ns
	gs.Spec = spec

	// sigs.k8s.io/yaml, not gopkg.in/yaml.v3: gs's fields carry only
	// `json:"..."` tags (the Kubernetes API convention), which yaml.v3
	// doesn't read at all -- it would emit lowercased Go field names
	// instead (apiversion, encryptedkey, ...) as discovered the first
	// time this command's real output was inspected rather than assumed
	// correct. sigs.k8s.io/yaml round-trips through encoding/json first,
	// so the emitted YAML keys match the struct tags exactly.
	out, err := sigsyaml.Marshal(gs)
	if err != nil {
		fmt.Fprintln(stderr, "error: marshal manifest:", err)
		return exitError
	}
	stdout.Write(out)
	return exitOK
}

// runRewrap implements --rewrap: read an existing GitSecret manifest,
// re-encrypt its content key to recipients (leaving encryptedData
// untouched), and print the result.
func runRewrap(path string, recipients []string, stdout, stderr io.Writer) int {
	if len(recipients) == 0 {
		fmt.Fprintln(stderr, "error: --rewrap requires at least one --recipient (the full new list, not just the one being added)")
		return exitUsage
	}
	if !gpgutil.Available() {
		fmt.Fprintln(stderr, "error: gpg binary not found on PATH")
		return exitError
	}

	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		fmt.Fprintln(stderr, "error: read", path, ":", err)
		return exitError
	}

	var gs v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(raw, &gs); err != nil {
		fmt.Fprintln(stderr, "error: parse", path, "as a GitSecret manifest:", err)
		return exitError
	}
	if gs.Kind != "" && gs.Kind != "GitSecret" {
		fmt.Fprintf(stderr, "error: %s is a %s manifest, not a GitSecret\n", path, gs.Kind)
		return exitUsage
	}

	newSpec, err := sealer.Rewrap(gs.Spec, recipients)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	gs.Spec = newSpec

	out, err := sigsyaml.Marshal(gs)
	if err != nil {
		fmt.Fprintln(stderr, "error: marshal manifest:", err)
		return exitError
	}
	stdout.Write(out)
	return exitOK
}

// readEnvFile parses simple KEY=VALUE lines, skipping blanks and #
// comments -- deliberately not a full .env-format parser (no quoting,
// no export, no interpolation) since the input is meant to be values a
// human or CI job already has in hand, not a shell environment to source.
func readEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	out := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s: line %q is not KEY=VALUE", path, line)
		}
		out[strings.TrimSpace(k)] = v
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return out, nil
}

// secretManifest is the minimal shape of a Secret manifest git-secret-seal
// reads -- deliberately not importing k8s.io/api/core/v1 for this one
// struct, to keep the manifest-reading path simple and dependency-light.
type secretManifest struct {
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
	StringData map[string]string `yaml:"stringData"`
}

// readSecretFile reads a Secret manifest (from path, or stdin if path is
// "-") and returns its plaintext values plus namespace/name. base64-decodes
// .data entries; .stringData entries are used as-is. Both may be present;
// stringData wins on key collision (matches Kubernetes' own merge rule).
func readSecretFile(path string) (map[string]string, string, string, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, "", "", fmt.Errorf("read %s: %w", path, err)
	}

	var sm secretManifest
	if err := yaml.Unmarshal(raw, &sm); err != nil {
		return nil, "", "", fmt.Errorf("parse %s: %w", path, err)
	}

	out := map[string]string{}
	for k, v := range sm.Data {
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, "", "", fmt.Errorf("%s: data[%q] is not valid base64: %w", path, k, err)
		}
		out[k] = string(decoded)
	}
	for k, v := range sm.StringData {
		out[k] = v
	}
	return out, sm.Metadata.Namespace, sm.Metadata.Name, nil
}
