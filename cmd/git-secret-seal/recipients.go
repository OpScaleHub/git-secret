package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

const recipientsHelp = `git-secret-seal recipients - inspect and change a GitSecret's recipient set

  git-secret-seal recipients list   -f FILE
  git-secret-seal recipients add    FPR -f FILE [--role human|controller|recovery|deprecated]
  git-secret-seal recipients remove FPR -f FILE [--force]

'add' and 'remove' rewrap the content key to the new recipient list (no
value is re-encrypted) and print the updated manifest on stdout. Both
require a local GPG secret key that can already open FILE's encryptedKey --
run them as one of the object's current recipients. 'add' additionally
needs FPR's public key in your keyring.

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

func recipientsList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipients list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", "", "path to the GitSecret manifest (- for stdin)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *file == "" {
		fmt.Fprintln(stderr, "error: -f FILE is required")
		return exitUsage
	}
	gs, err := readGitSecret(*file)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if len(gs.Spec.Recipients) == 0 {
		fmt.Fprintln(stderr, "note: spec.recipients is empty (sealed by an older git-secret-seal?)")
		return exitOK
	}
	roles := v1alpha1.ParseRecipientRoles(gs.Annotations)
	sorted := append([]string(nil), gs.Spec.Recipients...)
	sort.Strings(sorted)
	for _, fp := range sorted {
		role := roles[strings.ToUpper(fp)]
		if role == "" {
			role = v1alpha1.RoleHuman
		}
		fmt.Fprintf(stdout, "%s\t%s\n", fp, role)
	}
	return exitOK
}

func recipientsMutate(add bool, args []string, stdout, stderr io.Writer) int {
	verb := "add"
	if !add {
		verb = "remove"
	}
	fs := flag.NewFlagSet("recipients "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", "", "path to the GitSecret manifest (- for stdin)")
	role := fs.String("role", "", "role for the added recipient (human|controller|recovery|deprecated)")
	force := fs.Bool("force", false, "allow removing the last recipient or the last recovery recipient")
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
	if *file == "" {
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

	gs, err := readGitSecret(*file)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}

	current := map[string]bool{}
	for _, r := range gs.Spec.Recipients {
		current[strings.ToUpper(r)] = true
	}
	roles := v1alpha1.ParseRecipientRoles(gs.Annotations)
	key := strings.ToUpper(fpr)

	var next []string
	if add {
		if current[key] {
			fmt.Fprintf(stderr, "error: %s is already a recipient\n", fpr)
			return exitError
		}
		next = append(append([]string(nil), gs.Spec.Recipients...), fpr)
		if *role != "" {
			roles[key] = v1alpha1.RecipientRole(*role)
		}
	} else {
		if !current[key] {
			fmt.Fprintf(stderr, "error: %s is not a current recipient\n", fpr)
			return exitError
		}
		for _, r := range gs.Spec.Recipients {
			if strings.ToUpper(r) != key {
				next = append(next, r)
			}
		}
		if len(next) == 0 && !*force {
			fmt.Fprintln(stderr, "error: refusing to remove the last recipient (this would make the object permanently undecryptable); pass --force if you really mean it")
			return exitError
		}
		if !*force && roles[key] == v1alpha1.RoleRecovery && !hasRole(next, roles, v1alpha1.RoleRecovery) {
			fmt.Fprintln(stderr, "error: refusing to remove the last recovery recipient; pass --force to override")
			return exitError
		}
		delete(roles, key)
	}

	newSpec, err := sealer.Rewrap(gs.Spec, next)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	gs.Spec = newSpec

	roleStr := v1alpha1.FormatRecipientRoles(roles)
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

	out, err := sigsyaml.Marshal(gs)
	if err != nil {
		fmt.Fprintln(stderr, "error: marshal manifest:", err)
		return exitError
	}
	stdout.Write(out)
	return exitOK
}

func hasRole(fps []string, roles map[string]v1alpha1.RecipientRole, want v1alpha1.RecipientRole) bool {
	for _, fp := range fps {
		if roles[strings.ToUpper(fp)] == want {
			return true
		}
	}
	return false
}
