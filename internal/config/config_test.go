package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestMatchesPatternsAndExcludes(t *testing.T) {
	cfg := &Config{
		Version:    CurrentVersion,
		Patterns:   []string{"secrets/**/*.yaml", "*.secret.env"},
		Exclude:    []string{"secrets/public/*.yaml"},
		KeyBackend: "file",
		KeySource:  ".repo-enc/key",
	}

	cases := []struct {
		path string
		want bool
	}{
		{"secrets/prod/db.yaml", true},
		{"secrets/db.yaml", true},             // ** matches zero segments too
		{"secrets/public/db.yaml", false},     // excluded
		{"README.md", false},                  // no pattern match
		{".secret.env", true},                 // top-level pattern match
		{"nested/.secret.env", false},         // pattern has no ** so no nested match
		{"secrets/prod/nested/db.yaml", true}, // ** matches multiple segments
	}
	for _, tc := range cases {
		got, err := cfg.Matches(tc.path)
		if err != nil {
			t.Fatalf("Matches(%q): unexpected error: %v", tc.path, err)
		}
		if got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestLoadRepoLocalOverridesGlobalScalars(t *testing.T) {
	tmp := t.TempDir()
	repoRoot := filepath.Join(tmp, "repo")
	globalDir := filepath.Join(tmp, "globalcfg")
	t.Setenv("XDG_CONFIG_HOME", globalDir)

	writeFile(t, filepath.Join(globalDir, "repo-enc", "config.yml"), `
key_backend: env
key_source: MY_GLOBAL_KEY
patterns:
  - "*.secret.global"
`)
	writeFile(t, filepath.Join(repoRoot, FileName), `
version: 1
patterns:
  - "secrets/**"
key_backend: file
key_source: .repo-enc/key
`)

	cfg, err := Load(repoRoot)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.KeyBackend != "file" {
		t.Errorf("KeyBackend = %q, want repo-local override %q", cfg.KeyBackend, "file")
	}
	if cfg.KeySource != ".repo-enc/key" {
		t.Errorf("KeySource = %q, want repo-local override", cfg.KeySource)
	}
	// Patterns from both global and repo should be unioned.
	wantPatterns := map[string]bool{"*.secret.global": true, "secrets/**": true}
	if len(cfg.Patterns) != len(wantPatterns) {
		t.Fatalf("Patterns = %v, want union of global+repo (%v)", cfg.Patterns, wantPatterns)
	}
	for _, p := range cfg.Patterns {
		if !wantPatterns[p] {
			t.Errorf("unexpected pattern %q in merged config", p)
		}
	}
}

func TestLoadFallsBackToGlobalScalarWhenRepoOmits(t *testing.T) {
	tmp := t.TempDir()
	repoRoot := filepath.Join(tmp, "repo")
	globalDir := filepath.Join(tmp, "globalcfg")
	t.Setenv("XDG_CONFIG_HOME", globalDir)

	writeFile(t, filepath.Join(globalDir, "repo-enc", "config.yml"), `
key_backend: env
key_source: MY_GLOBAL_KEY
`)
	writeFile(t, filepath.Join(repoRoot, FileName), `
version: 1
patterns:
  - "secrets/**"
`)

	cfg, err := Load(repoRoot)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.KeyBackend != "env" || cfg.KeySource != "MY_GLOBAL_KEY" {
		t.Errorf("expected global scalars to apply, got backend=%q source=%q", cfg.KeyBackend, cfg.KeySource)
	}
}

func TestLoadMissingRepoConfigErrors(t *testing.T) {
	tmp := t.TempDir()
	if _, err := Load(tmp); err == nil {
		t.Fatalf("expected error loading missing repo config")
	}
}

func TestValidateRejectsBadConfig(t *testing.T) {
	cases := []*Config{
		{Version: 2, Patterns: []string{"a"}, KeyBackend: "file", KeySource: "k"},
		{Version: 1, Patterns: nil, KeyBackend: "file", KeySource: "k"},
		{Version: 1, Patterns: []string{"a"}, KeyBackend: "bogus", KeySource: "k"},
		{Version: 1, Patterns: []string{"a"}, KeyBackend: "file", KeySource: ""},
	}
	for i, cfg := range cases {
		if err := cfg.Validate(); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}

func TestWriteDefaultIsIdempotent(t *testing.T) {
	tmp := t.TempDir()
	path1, err := WriteDefault(tmp, []string{"secrets/**"})
	if err != nil {
		t.Fatalf("WriteDefault: %v", err)
	}
	data1, _ := os.ReadFile(path1)

	// Modify the file to simulate user edits, then call WriteDefault again.
	os.WriteFile(path1, append(data1, []byte("\n# user edit\n")...), 0o644)

	path2, err := WriteDefault(tmp, []string{"other/**"})
	if err != nil {
		t.Fatalf("WriteDefault (2nd call): %v", err)
	}
	if path1 != path2 {
		t.Fatalf("path changed between calls: %q vs %q", path1, path2)
	}
	data2, _ := os.ReadFile(path2)
	if string(data2) == string(data1) {
		t.Fatalf("expected user edit to survive idempotent WriteDefault call")
	}
	if !strings.Contains(string(data2), "# user edit") {
		t.Fatalf("user edit was lost: %s", data2)
	}
}
