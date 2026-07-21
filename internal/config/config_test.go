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
	t.Setenv(GlobalConfigDirEnvVar, globalDir)

	writeFile(t, filepath.Join(globalDir, "config.yml"), `
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

// TestMatchesNormalizesLeadingSlashInPattern pins the fix for issue #20:
// a root-anchored pattern like "/secrets/**" validated but matched
// nothing, since splitting on "/" produced a leading empty segment that
// can never match a real path segment — hooks/verify failed open with
// no error.
func TestMatchesNormalizesLeadingSlashInPattern(t *testing.T) {
	cfg := &Config{
		Version:    CurrentVersion,
		Patterns:   []string{"/secrets/**"},
		KeyBackend: "file",
		KeySource:  ".repo-enc/key",
	}
	matched, err := cfg.Matches("secrets/db.env")
	if err != nil {
		t.Fatalf("Matches: %v", err)
	}
	if !matched {
		t.Fatalf("root-anchored pattern /secrets/** should match secrets/db.env, but failed open")
	}
}

func TestLoadFallsBackToGlobalScalarWhenRepoOmits(t *testing.T) {
	tmp := t.TempDir()
	repoRoot := filepath.Join(tmp, "repo")
	globalDir := filepath.Join(tmp, "globalcfg")
	t.Setenv(GlobalConfigDirEnvVar, globalDir)

	writeFile(t, filepath.Join(globalDir, "config.yml"), `
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

// TestGlobalExcludeCannotWeakenRepoPolicy pins the fix for issue #16: a
// machine-local global config used to be unioned into repo Exclude,
// letting a stale/overly-broad global config silently carve a hole out
// of a repo's committed encryption policy with no diff to review.
func TestGlobalExcludeCannotWeakenRepoPolicy(t *testing.T) {
	tmp := t.TempDir()
	repoRoot := filepath.Join(tmp, "repo")
	globalDir := filepath.Join(tmp, "globalcfg")
	t.Setenv(GlobalConfigDirEnvVar, globalDir)

	writeFile(t, filepath.Join(globalDir, "config.yml"), `
exclude:
  - "secrets/**"
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
	matched, err := cfg.Matches("secrets/db.env")
	if err != nil {
		t.Fatalf("Matches: %v", err)
	}
	if !matched {
		t.Fatalf("a machine-local global exclude silently weakened repo policy: secrets/db.env should still match")
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
		{Version: 1, Patterns: []string{"a"}, KeyBackend: "gpg", KeySource: "k"}, // gpg requires gpg_recipients
		{Version: 1, Patterns: nil, K8sSecretPaths: nil, KeyBackend: "file", KeySource: "k"},
	}
	for i, cfg := range cases {
		if err := cfg.Validate(); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}

func TestValidateAcceptsK8sSecretPathsWithoutPatterns(t *testing.T) {
	cfg := &Config{
		Version:        CurrentVersion,
		K8sSecretPaths: []string{"deploy/api-secrets.yaml"},
		KeyBackend:     "file",
		KeySource:      ".repo-enc/key",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: unexpected error with only k8s_secret_paths set: %v", err)
	}
}

func TestMergeIntoUnionsK8sSecretPaths(t *testing.T) {
	base := &Config{K8sSecretPaths: []string{"a.yaml"}}
	overlay := &Config{K8sSecretPaths: []string{"b.yaml", "a.yaml"}}
	mergeInto(base, overlay)
	if len(base.K8sSecretPaths) != 2 {
		t.Fatalf("K8sSecretPaths = %v, want union-deduped [a.yaml b.yaml]", base.K8sSecretPaths)
	}
}

func TestLoadRoundTripsK8sSecretPaths(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, FileName), `
version: 1
k8s_secret_paths:
  - "deploy/api-secrets.yaml"
key_backend: file
key_source: .repo-enc/key
`)
	cfg, err := Load(tmp)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.K8sSecretPaths) != 1 || cfg.K8sSecretPaths[0] != "deploy/api-secrets.yaml" {
		t.Fatalf("K8sSecretPaths = %v, want [deploy/api-secrets.yaml]", cfg.K8sSecretPaths)
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

func TestValidateAcceptsGPGBackendWithRecipients(t *testing.T) {
	cfg := &Config{
		Version: CurrentVersion, Patterns: []string{"secrets/**"},
		KeyBackend: "gpg", KeySource: DefaultKeySourceFor("gpg"),
		GPGRecipients: []string{"AAAABBBBCCCCDDDD1111222233334444AAAABBBB"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
}

func TestDefaultKeySourceForDiffersByBackend(t *testing.T) {
	if DefaultKeySourceFor("file") == DefaultKeySourceFor("gpg") {
		t.Fatalf("file and gpg backends should not share a default key_source (one is gitignored/secret, the other is meant to be committed)")
	}
}

func TestWriteConfigIdempotentLikeWriteDefault(t *testing.T) {
	tmp := t.TempDir()
	cfg := &Config{
		Version: CurrentVersion, Patterns: []string{"secrets/**"},
		KeyBackend: "gpg", KeySource: DefaultKeySourceFor("gpg"),
		GPGRecipients: []string{"AAAABBBBCCCCDDDD1111222233334444AAAABBBB"},
	}
	path1, err := WriteConfig(tmp, cfg)
	if err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	// A second call with different content must not overwrite.
	otherCfg := &Config{Version: CurrentVersion, Patterns: []string{"other/**"}, KeyBackend: "file", KeySource: DefaultKeySourceFor("file")}
	path2, err := WriteConfig(tmp, otherCfg)
	if err != nil {
		t.Fatalf("WriteConfig (2nd call): %v", err)
	}
	if path1 != path2 {
		t.Fatalf("path changed between calls")
	}
	loaded, err := loadFile(path2)
	if err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	if loaded.KeyBackend != "gpg" {
		t.Fatalf("KeyBackend = %q, want gpg to survive the idempotent 2nd call", loaded.KeyBackend)
	}
}

func TestSaveOverwritesUnconditionally(t *testing.T) {
	tmp := t.TempDir()
	cfg := &Config{Version: CurrentVersion, Patterns: []string{"secrets/**"}, KeyBackend: "file", KeySource: DefaultKeySourceFor("file")}
	if _, err := WriteConfig(tmp, cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	updated := &Config{
		Version: CurrentVersion, Patterns: []string{"secrets/**"},
		KeyBackend: "gpg", KeySource: DefaultKeySourceFor("gpg"),
		GPGRecipients: []string{"AAAABBBBCCCCDDDD1111222233334444AAAABBBB", "1111222233334444AAAABBBBCCCCDDDD11112222"},
	}
	if err := Save(tmp, updated); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := loadFile(filepath.Join(tmp, FileName))
	if err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	if loaded.KeyBackend != "gpg" || len(loaded.GPGRecipients) != 2 {
		t.Fatalf("Save did not overwrite: got %+v", loaded)
	}
}

func TestMergeIntoUnionsGPGRecipients(t *testing.T) {
	base := &Config{GPGRecipients: []string{"AAAA"}}
	overlay := &Config{GPGRecipients: []string{"BBBB", "AAAA"}}
	mergeInto(base, overlay)
	if len(base.GPGRecipients) != 2 {
		t.Fatalf("GPGRecipients = %v, want union-deduped [AAAA BBBB]", base.GPGRecipients)
	}
}
