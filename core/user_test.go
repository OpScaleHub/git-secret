package core

import (
	"os"
	"testing"
)

func TestAddUserKey(t *testing.T) {
	dir := ".testsecret"
	os.MkdirAll(dir, 0o700)
	defer os.RemoveAll(dir)
	cfg := &Config{SecretDir: dir}
	key := "TESTKEY123"
	if err := AddUserKey(key, cfg); err != nil {
		t.Fatalf("AddUserKey failed: %v", err)
	}
	if err := AddUserKey(key, cfg); err != nil {
		t.Fatalf("AddUserKey duplicate failed: %v", err)
	}
	data, err := os.ReadFile(dir + "/users")
	if err != nil {
		t.Fatalf("Read users failed: %v", err)
	}
	lines := string(data)
	if lines != key+"\n" {
		t.Errorf("Expected users file to contain only the key, got: %q", lines)
	}
}
