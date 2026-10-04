package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/OpScaleHub/keyfold/api/v1alpha1"
)

const migrateHelp = `keyfold migrate - move manifests to the keyfold.opscalehub.io API group

  keyfold migrate -f PATH [-f PATH ...] [--dry-run]

Rewrites, in place, every YAML file under each PATH (a file or a
directory; .yaml/.yml, .git skipped):

  apiVersion: git-secret.opscalehub.io/v1alpha1  ->  keyfold.opscalehub.io/v1alpha1
  git-secret.opscalehub.io/<annotation>:         ->  keyfold.opscalehub.io/<annotation>:

Only those two positions change -- comments, formatting and every
ciphertext stay byte-for-byte as they were, and nothing is re-sealed (a
GitSecret's ciphertext is bound to namespace/name/key, never to the API
group). Namespace manifests carrying the required-recipients annotation
are migrated the same way. See UPGRADING.md for the cluster-side steps.

  --dry-run    report what would change, write nothing
`

var (
	legacyAPIVersionLine = regexp.MustCompile(`(?m)^(\s*apiVersion:\s*["']?)` + regexp.QuoteMeta(v1alpha1.LegacyGroup) + `/`)
	legacyAnnotationKey  = regexp.MustCompile(`(?m)^(\s*(?:-\s+)?["']?)` + regexp.QuoteMeta(v1alpha1.LegacyGroup) + `/([A-Za-z0-9._-]+["']?\s*:)`)
)

func runMigrate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keyfold migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var paths stringSlice
	fs.Var(&paths, "f", "file or directory to migrate (repeatable)")
	dryRun := fs.Bool("dry-run", false, "report what would change without writing")
	if err := fs.Parse(args); err != nil {
		fmt.Fprint(stderr, migrateHelp)
		return exitUsage
	}
	if len(paths) == 0 {
		fmt.Fprint(stderr, migrateHelp)
		return exitUsage
	}

	var files []string
	for _, p := range paths {
		found, err := yamlFiles(p)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		files = append(files, found...)
	}

	changedFiles, changes := 0, 0
	for _, f := range files {
		n, err := migrateFile(f, *dryRun)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		if n > 0 {
			changedFiles++
			changes += n
			fmt.Fprintf(stdout, "%s: %d change(s)\n", f, n)
		}
	}
	verb := "migrated"
	if *dryRun {
		verb = "would migrate"
	}
	fmt.Fprintf(stdout, "%s %d reference(s) in %d of %d file(s)\n", verb, changes, changedFiles, len(files))
	return exitOK
}

// migrateFile rewrites one file and returns how many references changed.
// The result must still parse as YAML, or nothing is written.
func migrateFile(path string, dryRun bool) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := len(legacyAPIVersionLine.FindAllIndex(raw, -1)) + len(legacyAnnotationKey.FindAllIndex(raw, -1))
	if n == 0 {
		return 0, nil
	}
	out := legacyAPIVersionLine.ReplaceAll(raw, []byte("${1}"+v1alpha1.GroupVersion.Group+"/"))
	out = legacyAnnotationKey.ReplaceAll(out, []byte("${1}"+v1alpha1.GroupVersion.Group+"/${2}"))
	if err := parsesAsYAML(out); err != nil {
		return 0, fmt.Errorf("%s: rewritten file no longer parses, left untouched: %w", path, err)
	}
	if dryRun {
		return n, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return n, os.WriteFile(path, out, info.Mode().Perm())
}

func parsesAsYAML(b []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func yamlFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var out []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := strings.ToLower(filepath.Ext(p)); ext == ".yaml" || ext == ".yml" {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}
