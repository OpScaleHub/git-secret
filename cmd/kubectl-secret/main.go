// Command kubectl-secret is a kubectl plugin (invoked as `kubectl secret
// <verb>`) that lets a Kubernetes Secret manifest carry per-key ciphertext
// for its stringData entries, instead of git-secret's whole-file
// encryption. It reuses git-secret's crypto core and key backends
// unchanged. See proposals/0001-kubectl-secret-plugin.md for the design.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/OpScaleHub/git-secret/internal/cli"
	"github.com/OpScaleHub/git-secret/keybackend"
	"gopkg.in/yaml.v3"
)

// version is stamped at build time via:
//
//	go build -ldflags "-X main.version=v1.2.3" ./cmd/kubectl-secret
//
// A plain `go build` leaves it at "dev"; cmdVersion falls back to Go's own
// build info (module version/vcs revision) in that case.
var version = "dev"

const helpText = `kubectl-secret - per-value encryption for Kubernetes Secret manifests

Usage: kubectl secret <verb> [args]

Verbs:
  apply         -f FILE [-n NAMESPACE]   Decrypt matched stringData values
                                          in memory and 'kubectl apply' the
                                          result. Never writes plaintext to
                                          disk. -n must match the namespace
                                          each value was encrypted for, or
                                          decryption fails closed.
  create        -f FILE [-n NAMESPACE]   Same, but 'kubectl create'.
  view          -f FILE                  Print the fully-decrypted manifest
                                          to stdout. Never writes it to disk.
  encrypt-value -f FILE -k KEY            Emit a repo-enc:v1:... blob bound
    < plaintext                          to FILE/KEY/the object identity
                                          (apiVersion/kind/name/namespace),
                                          to paste into stringData by hand.
                                          Reads the value from stdin;
                                          --allow-argv uses a CLI argument
                                          instead (visible in shell
                                          history/process listings).
  version                                Show version information.
  help                                   Show this help.

FILE must be listed under k8s_secret_paths in .repo-enc.yml, and must
already declare apiVersion/kind/metadata.name before encrypt-value can
bind a value to it.

Exit codes: 0 ok, 1 error, 2 key unavailable.
`

// Exit codes, mirroring git-secret's own (minus exitVerifyFound, which
// has no equivalent here).
const (
	exitOK         = 0
	exitError      = 1
	exitKeyMissing = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Print(helpText)
		return exitError
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(helpText)
		return exitOK
	case "version", "-v", "--version":
		return cmdVersion()
	case "apply":
		return cmdApplyCreate("apply", args[1:])
	case "create":
		return cmdApplyCreate("create", args[1:])
	case "view":
		return cmdView(args[1:])
	case "encrypt-value":
		return cmdEncryptValue(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown verb: %s\n\n", args[0])
		fmt.Print(helpText)
		return exitError
	}
}

// cmdVersion prints the release version when this binary was built with
// -ldflags, or falls back to Go's own build info (module version, VCS
// revision/dirty state) for a plain `go build`.
func cmdVersion() int {
	v := version
	var commit, buildTime string
	dirty := false
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				commit = s.Value
			case "vcs.time":
				buildTime = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
	}
	fmt.Printf("kubectl-secret %s\n", v)
	if commit != "" {
		if len(commit) > 12 {
			commit = commit[:12]
		}
		if dirty {
			commit += "-dirty"
		}
		fmt.Printf("  commit:  %s\n", commit)
	}
	if buildTime != "" {
		fmt.Printf("  built:   %s\n", buildTime)
	}
	fmt.Printf("  go:      %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return exitOK
}

// cmdApplyCreate implements both `apply` and `create`: decrypt the
// manifest's stringData values in memory, then pipe the result to the
// real kubectl binary on PATH. Plaintext exists only in this process's
// memory and the pipe to the kubectl child — it is never written to disk.
func cmdApplyCreate(verb string, args []string) int {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "path to the Secret manifest (required)")
	namespace := fs.String("n", "", "namespace to pass through to kubectl")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitError
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, "Error: -f FILE is required")
		return exitError
	}

	kubectlPath, err := exec.LookPath("kubectl")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: kubectl not found on PATH")
		return exitError
	}

	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	relPath, err := repoRelativePath(ctx.RepoRoot, *file)
	if err != nil {
		return fail(err)
	}
	decrypted, err := ctx.DecryptK8sManifest(relPath, *namespace)
	if err != nil {
		return fail(err)
	}
	warnIfArgoCDManaged(decrypted, verb)

	kubectlArgs := []string{verb, "-f", "-"}
	if *namespace != "" {
		kubectlArgs = append(kubectlArgs, "-n", *namespace)
	}
	cmd := exec.Command(kubectlPath, kubectlArgs...)
	cmd.Stdin = bytes.NewReader(decrypted)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: kubectl %s failed: %v\n", verb, err)
		return exitError
	}
	return exitOK
}

// cmdView decrypts the manifest and prints it to stdout, never touching
// disk or invoking kubectl — useful for eyeballing what apply would send.
func cmdView(args []string) int {
	fs := flag.NewFlagSet("view", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "path to the Secret manifest (required)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitError
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, "Error: -f FILE is required")
		return exitError
	}

	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	relPath, err := repoRelativePath(ctx.RepoRoot, *file)
	if err != nil {
		return fail(err)
	}
	decrypted, err := ctx.DecryptK8sManifest(relPath, "")
	if err != nil {
		return fail(err)
	}
	os.Stdout.Write(decrypted)
	return exitOK
}

// cmdEncryptValue seals a single plaintext value for a specific (file,
// key) pair and prints the repo-enc:v1:... blob for the user to paste
// into the manifest by hand. -f/-k are required (rather than just taking
// a bare plaintext argument) because per-value ciphertext is bound to
// both the destination file and stringData key as AAD, blocking
// ciphertext from being swapped between keys within the same manifest.
//
// The plaintext itself is read from stdin by default, not argv: a bare
// CLI argument lands in shell history and is visible to any other local
// process (ps/proc) for the life of this command — exactly the class of
// leak apply/view/create otherwise avoid by never writing plaintext to
// disk. --allow-argv keeps the old positional-argument form for quick
// interactive use, with a loud warning.
func cmdEncryptValue(args []string) int {
	fs := flag.NewFlagSet("encrypt-value", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "path to the Secret manifest (required)")
	key := fs.String("k", "", "stringData key this value will be stored under (required)")
	allowArgv := fs.Bool("allow-argv", false, "read the plaintext from a bare CLI argument instead of stdin (leaves it in shell history/process listings -- prefer piping via stdin)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitError
	}
	if *file == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "Error: usage: echo -n VALUE | kubectl secret encrypt-value -f FILE -k KEY")
		return exitError
	}

	var plaintext string
	if *allowArgv {
		plaintextArgs := fs.Args()
		if len(plaintextArgs) != 1 {
			fmt.Fprintln(os.Stderr, "Error: --allow-argv requires exactly one plaintext argument")
			return exitError
		}
		fmt.Fprintln(os.Stderr, "Warning: --allow-argv leaves the plaintext value in shell history and visible to other local processes for the life of this command.")
		plaintext = plaintextArgs[0]
	} else {
		if len(fs.Args()) != 0 {
			fmt.Fprintln(os.Stderr, "Error: plaintext is read from stdin by default -- pass --allow-argv to use a bare CLI argument instead")
			return exitError
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: read plaintext from stdin: %v\n", err)
			return exitError
		}
		plaintext = strings.TrimSuffix(string(data), "\n")
	}

	ctx, err := cli.Load()
	if err != nil {
		return fail(err)
	}
	relPath, err := repoRelativePath(ctx.RepoRoot, *file)
	if err != nil {
		return fail(err)
	}
	blob, err := ctx.EncryptK8sValue(relPath, *key, plaintext)
	if err != nil {
		return fail(err)
	}
	fmt.Println(blob)
	return exitOK
}

// warnIfArgoCDManaged prints a warning to stderr if decrypted carries
// the argocd.argoproj.io/instance label. That label is a cheap,
// deterministic signal that the object is also managed by an ArgoCD
// Application; if that Application has syncPolicy.automated.selfHeal
// enabled (not something this manifest alone can tell us), a direct
// `apply`/`create` here can be silently reverted on ArgoCD's next
// reconcile with no error on either side — confirmed live: a
// hand-corrected value reverted within seconds. Best-effort only: any
// parse failure just skips the warning rather than blocking the command.
func warnIfArgoCDManaged(decrypted []byte, verb string) {
	var doc yaml.Node
	if err := yaml.Unmarshal(decrypted, &doc); err != nil || len(doc.Content) == 0 {
		return
	}
	root := doc.Content[0]
	labels := yamlLookup(yamlLookup(root, "metadata"), "labels")
	if labels == nil || labels.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(labels.Content); i += 2 {
		if labels.Content[i].Value != "argocd.argoproj.io/instance" {
			continue
		}
		fmt.Fprintf(os.Stderr, "Warning: this Secret carries the argocd.argoproj.io/instance label (ArgoCD app %q). If that Application has syncPolicy.automated.selfHeal enabled, a direct `kubectl secret %s` can be silently reverted on ArgoCD's next reconcile. Prefer commit + push + `argocd app sync`/`--hard-refresh` for ArgoCD-managed secrets; treat apply/create as local-cluster or bootstrap-only.\n", labels.Content[i+1].Value, verb)
		return
	}
}

// yamlLookup returns the value node for key in mapping node m, or nil if
// m isn't a mapping or doesn't have key.
func yamlLookup(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// repoRelativePath resolves f (absolute, or relative to the current
// working directory) to a slash-separated path relative to repoRoot —
// the same form k8s_secret_paths entries in .repo-enc.yml use.
func repoRelativePath(repoRoot, f string) (string, error) {
	abs, err := filepath.Abs(f)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", f, err)
	}
	rel, err := filepath.Rel(repoRoot, abs)
	if err != nil {
		return "", fmt.Errorf("resolve %s relative to repo root: %w", f, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the repo root %s", f, repoRoot)
	}
	return filepath.ToSlash(rel), nil
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	if errors.Is(err, keybackend.ErrKeyNotFound) {
		return exitKeyMissing
	}
	return exitError
}
