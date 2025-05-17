package core

import (
	"os"
	"testing"
)

func TestCreateSecretDir(t *testing.T) {
	dir := ".testsecretdir"
	defer os.RemoveAll(dir)
	if err := CreateSecretDir(dir); err != nil {
		t.Fatalf("CreateSecretDir failed: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("Secret dir not created: %v", err)
	}
}

func TestUpdateGitIgnoreEntry(t *testing.T) {
	file := ".testignore"
	defer os.Remove(file)
	os.WriteFile(file, []byte("foo\n"), 0o644)
	if err := UpdateGitIgnoreEntry("bar.txt"); err != nil {
		t.Fatalf("UpdateGitIgnoreEntry failed: %v", err)
	}
	data, _ := os.ReadFile(file)
	if string(data) != "foo\nbar.txt\n" && string(data) != "foo\nbar.txt\n" {
		t.Errorf(".gitignore entry not added: %q", string(data))
	}
}
