package core

import (
	"os/exec"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Backend != "gpg" {
		t.Errorf("Expected default backend 'gpg', got %q", cfg.Backend)
	}
	if cfg.SecretDir != ".gitsecret" {
		t.Errorf("Expected default secret dir '.gitsecret', got %q", cfg.SecretDir)
	}
}

func TestGetGitConfig_Fallback(t *testing.T) {
	val := getGitConfig("this.key.does.not.exist", "fallback-value")
	if val != "fallback-value" {
		t.Errorf("Expected fallback value, got %q", val)
	}
}

func TestGetGitConfig_RealGit(t *testing.T) {
	// Set a git config value and test retrieval
	key := "secret.testkey"
	val := "testval"
	exec.Command("git", "config", "--local", key, val).Run()
	got := getGitConfig(key, "fallback")
	if got != val {
		t.Errorf("Expected git config value %q, got %q", val, got)
	}
	// Clean up
	exec.Command("git", "config", "--unset", key).Run()
}
