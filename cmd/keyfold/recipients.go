package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/keyfold/api/v1alpha1"
	"github.com/OpScaleHub/keyfold/internal/gpgutil"
	"github.com/OpScaleHub/keyfold/internal/sealer"
)

const recipientsHelp = `keyfold recipients - inspect and change a GitSecret's recipient set

  keyfold recipients list   -f PATH [-f PATH ...]
  keyfold recipients add    FPR -f PATH [-f PATH ...] [--role ROLE] [--write|--dry-run] [--keyring SRC]
  keyfold recipients remove FPR -f PATH [-f PATH ...] [--force] [--write|--dry-run] [--keyring SRC]

PATH is a GitSecret manifest, a directory (every single-document GitSecret
under it), or - for stdin. With one manifest and no --write, the updated
manifest is printed on stdout. Several files or a directory need --write
(rewrite in place) or --dry-run (preview); every file is computed first,
and if any one fails nothing is written. Objects that already have (or
already lack) FPR are left alone.

'add' and 'remove' rewrap the content key to the new recipient list (no
value is re-encrypted). Both need a local GPG secret key that can already
open each object -- run them as one of its current recipients -- and the
public key of every recipient the result is wrapped to: in your keyring,
or as publicKey entries in --keyring (used for this run only, each checked
to be exactly the key its fingerprint names; never imported). A new
cluster's public key alone can never add itself: only an existing
recipient can.

'remove' refuses to drop the last recipient, or the last recipient with
role 'recovery', unless --force is given.
`

func runRecipients(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, recipientsHelp)
		return exitUsage
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		return recipientsList(rest, stdout, stderr)
	case "add":
		return recipientsMutate(true, rest, stdout, stderr)
	case "remove":
		return recipientsMutate(false, rest, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stderr, recipientsHelp)
		return exitUsage
	default:
		fmt.Fprintf(stderr, "error: unknown recipients subcommand %q\n\n%s", sub, recipientsHelp)
		return exitUsage
	}
}

func readGitSecret(path string) (*v1alpha1.GitSecret, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var gs v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(raw, &gs); err != nil {
		return nil, fmt.Errorf("parse %s as a GitSecret manifest: %w", path, err)
	}
	if gs.Kind != "" && gs.Kind != "GitSecret" {
		return nil, fmt.Errorf("%s is a %s manifest, not a GitSecret", path, gs.Kind)
	}
	return &gs, nil
}

// recipientTarget is one manifest a recipients command operates on.
type recipientTarget struct {
	path    string
	fromDir bool // found by walking a directory: non-GitSecret YAML is skipped, not an error
}

// resolveTargets expands -f values: a file, "-" (stdin, alone), or a
// directory walked for .yaml/.yml files.
func resolveTargets(paths []string) ([]recipientTarget, bool, error) {
	var out []recipientTarget
	sawDir := false
	for _, p := range paths {
		if p == "-" {
			if len(paths) != 1 {
				return nil, false, fmt.Errorf("-f - (stdin) cannot be combined with other -f values")
			}
			return []recipientTarget{{path: "-"}}, false, nil
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, false, err
		}
		if !info.IsDir() {
			out = append(out, recipientTarget{path: p})
			continue
		}
		sawDir = true
		files, err := yamlFiles(p)
		if err != nil {
			return nil, false, err
		}
		for _, f := range files {
			out = append(out, recipientTarget{path: f, fromDir: true})
		}
	}
	return out, sawDir, nil
}

// readSingleGitSecret reads a file that must hold exactly one YAML document
// of kind GitSecret. Bulk mode refuses anything else: re-marshalling a
// multi-document file would silently drop every document but the first.
func readSingleGitSecret(path string) (*v1alpha1.GitSecret, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if n, err := countYAMLDocs(raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	} else if n != 1 {
		return nil, fmt.Errorf("%s holds %d YAML documents; bulk mode only rewrites single-document GitSecret files", path, n)
	}
	var gs v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal(raw, &gs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if gs.Kind != "GitSecret" {
		return nil, fmt.Errorf("%s is not a GitSecret (kind %q)", path, gs.Kind)
	}
	return &gs, nil
}

func countYAMLDocs(b []byte) (int, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	n := 0
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
		if len(doc.Content) > 0 {
			n++
		}
	}
}

func recipientsList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipients list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files stringSlice
	fs.Var(&files, "f", "GitSecret manifest, directory, or - for stdin (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "error: -f FILE is required")
		return exitUsage
	}
	targets, sawDir, err := resolveTargets(files)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if len(targets) == 1 && !sawDir {
		gs, err := readGitSecret(targets[0].path)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		if len(gs.Spec.Recipients) == 0 {
			fmt.Fprintln(stderr, "note: spec.recipients is empty (sealed by an older keyfold?)")
			return exitOK
		}
		for _, line := range recipientLines(gs) {
			fmt.Fprintln(stdout, line)
		}
		return exitOK
	}
	for _, t := range targets {
		gs, err := readSingleGitSecret(t.path)
		if err != nil {
			if t.fromDir {
				continue
			}
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		for _, line := range recipientLines(gs) {
			fmt.Fprintf(stdout, "%s\t%s\n", t.path, line)
		}
	}
	return exitOK
}

func recipientLines(gs *v1alpha1.GitSecret) []string {
	roles := v1alpha1.ParseRecipientRoles(gs.Annotations)
	sorted := append([]string(nil), gs.Spec.Recipients...)
	sort.Strings(sorted)
	var out []string
	for _, fp := range sorted {
		role := roles[strings.ToUpper(fp)]
		if role == "" {
			role = v1alpha1.RoleHuman
		}
		out = append(out, fmt.Sprintf("%s\t%s", fp, role))
	}
	return out
}

// errNoChange marks a recipient change that is already in effect for an
// object (adding a present recipient, removing an absent one).
var errNoChange = errors.New("no change")

// applyRecipientChange rewraps gs to add or remove fpr in place.
func applyRecipientChange(gs *v1alpha1.GitSecret, add bool, fpr, role string, force bool) error {
	current := map[string]bool{}
	for _, r := range gs.Spec.Recipients {
		current[strings.ToUpper(r)] = true
	}
	roles := v1alpha1.ParseRecipientRoles(gs.Annotations)
	key := strings.ToUpper(fpr)

	var next []string
	if add {
		if current[key] {
			return fmt.Errorf("%w: %s is already a recipient", errNoChange, fpr)
		}
		next = append(append([]string(nil), gs.Spec.Recipients...), fpr)
		if role != "" {
			roles[key] = v1alpha1.RecipientRole(role)
		}
	} else {
		if !current[key] {
			return fmt.Errorf("%w: %s is not a current recipient", errNoChange, fpr)
		}
		for _, r := range gs.Spec.Recipients {
			if strings.ToUpper(r) != key {
				next = append(next, r)
			}
		}
		if len(next) == 0 && !force {
			return fmt.Errorf("refusing to remove the last recipient (this would make the object permanently undecryptable); pass --force if you really mean it")
		}
		if !force && roles[key] == v1alpha1.RoleRecovery && !hasRole(next, roles, v1alpha1.RoleRecovery) {
			return fmt.Errorf("refusing to remove the last recovery recipient; pass --force to override")
		}
		delete(roles, key)
	}

	newSpec, err := sealer.Rewrap(gs.Spec, next)
	if err != nil {
		if strings.Contains(err.Error(), "No secret key") {
			return explainUnwrapError(err, gs)
		}
		return explainWrapError(err)
	}
	gs.Spec = newSpec

	roleStr := v1alpha1.FormatRecipientRoles(roles)
	// Roles are always written under the current key; drop a pre-rename one
	// so the object never carries two disagreeing role lists.
	delete(gs.Annotations, v1alpha1.LegacyAnnotationKey(v1alpha1.RecipientRolesAnnotation))
	if roleStr == "" {
		delete(gs.Annotations, v1alpha1.RecipientRolesAnnotation)
		if len(gs.Annotations) == 0 {
			gs.Annotations = nil
		}
	} else {
		if gs.Annotations == nil {
			gs.Annotations = map[string]string{}
		}
		gs.Annotations[v1alpha1.RecipientRolesAnnotation] = roleStr
	}
	return nil
}

func recipientsMutate(add bool, args []string, stdout, stderr io.Writer) int {
	verb := "add"
	if !add {
		verb = "remove"
	}
	fs := flag.NewFlagSet("recipients "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files stringSlice
	fs.Var(&files, "f", "GitSecret manifest, directory, or - for stdin (repeatable)")
	role := fs.String("role", "", "role for the added recipient (human|controller|recovery|deprecated)")
	force := fs.Bool("force", false, "allow removing the last recipient or the last recovery recipient")
	write := fs.Bool("write", false, "rewrite the files in place (required for several files or a directory)")
	dryRun := fs.Bool("dry-run", false, "report what would change, write nothing")
	keyringSrc := fs.String("keyring", "", "keyring file or URL whose embedded publicKeys are used for wrapping (never imported into your keyring)")
	// Two-pass parse so the fingerprint positional can appear before or
	// after the flags (Go's flag package otherwise stops at the first
	// non-flag token).
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	var fpr string
	if rest := fs.Args(); len(rest) > 0 {
		fpr = rest[0]
		if err := fs.Parse(rest[1:]); err != nil {
			return exitUsage
		}
	}
	if fpr == "" || fs.NArg() != 0 {
		fmt.Fprintf(stderr, "error: exactly one fingerprint argument is required\n\n%s", recipientsHelp)
		return exitUsage
	}
	if !gpgutil.ValidFingerprint(fpr) {
		fmt.Fprintf(stderr, "error: %q is not a full 40/64-hex GPG fingerprint\n", fpr)
		return exitUsage
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "error: -f FILE is required")
		return exitUsage
	}
	if !add && *role != "" {
		fmt.Fprintln(stderr, "error: --role only applies to 'add'")
		return exitUsage
	}
	if *role != "" && !v1alpha1.ValidRecipientRole(v1alpha1.RecipientRole(*role)) {
		fmt.Fprintf(stderr, "error: %q is not a valid role (human|controller|recovery|deprecated)\n", *role)
		return exitUsage
	}
	if !gpgutil.Available() {
		fmt.Fprintln(stderr, "error: gpg binary not found on PATH")
		return exitError
	}
	targets, sawDir, err := resolveTargets(files)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if *keyringSrc != "" {
		cleanup, err := useKeyringPublicKeys(*keyringSrc)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		defer cleanup()
	}

	// One manifest, no --write: print the result (the original behaviour).
	if len(targets) == 1 && !sawDir && !*write && !*dryRun {
		gs, err := readGitSecret(targets[0].path)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		if err := applyRecipientChange(gs, add, fpr, *role, *force); err != nil {
			fmt.Fprintln(stderr, "error:", strings.TrimPrefix(err.Error(), errNoChange.Error()+": "))
			return exitError
		}
		out, err := marshalManifest(gs)
		if err != nil {
			fmt.Fprintln(stderr, "error: marshal manifest:", err)
			return exitError
		}
		stdout.Write(out)
		return exitOK
	}
	if !*write && !*dryRun {
		fmt.Fprintln(stderr, "error: several files or a directory need --write (or --dry-run to preview)")
		return exitUsage
	}
	if targets[0].path == "-" {
		fmt.Fprintln(stderr, "error: --write and --dry-run need files, not stdin")
		return exitUsage
	}

	// Compute every result before writing anything: one failure (no key,
	// last-recovery guard, a malformed file) leaves every file untouched.
	type result struct {
		path string
		out  []byte
		mode os.FileMode
	}
	var changed []result
	unchanged, skipped := 0, 0
	var failures []string
	for _, t := range targets {
		gs, err := readSingleGitSecret(t.path)
		if err != nil {
			if t.fromDir {
				skipped++
				continue
			}
			failures = append(failures, err.Error())
			continue
		}
		if err := applyRecipientChange(gs, add, fpr, *role, *force); err != nil {
			if errors.Is(err, errNoChange) {
				unchanged++
				continue
			}
			failures = append(failures, fmt.Sprintf("%s: %v", t.path, err))
			continue
		}
		out, err := marshalManifest(gs)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: marshal: %v", t.path, err))
			continue
		}
		info, err := os.Stat(t.path)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		changed = append(changed, result{t.path, out, info.Mode().Perm()})
	}
	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Fprintln(stderr, "error:", f)
		}
		fmt.Fprintf(stderr, "nothing written: %d file(s) failed\n", len(failures))
		return exitError
	}
	for _, r := range changed {
		if *dryRun {
			fmt.Fprintf(stdout, "would rewrap %s\n", r.path)
			continue
		}
		if err := writeFileAtomic(r.path, r.out, r.mode); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		fmt.Fprintf(stdout, "rewrapped %s\n", r.path)
	}
	what := verb + "ed"
	if !add {
		what = "removed"
	}
	if *dryRun {
		what = "would be " + what
	}
	fmt.Fprintf(stdout, "%s %s: %d changed, %d already done, %d skipped (not single-document GitSecrets)\n", fpr, what, len(changed), unchanged, skipped)
	return exitOK
}

// writeFileAtomic replaces path via a temp file in the same directory.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func hasRole(fps []string, roles map[string]v1alpha1.RecipientRole, want v1alpha1.RecipientRole) bool {
	for _, fp := range fps {
		if roles[strings.ToUpper(fp)] == want {
			return true
		}
	}
	return false
}
