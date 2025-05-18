package cmd

import (
	"os"
	"os/exec"
	"testing"
)

func TestCLI_Help(t *testing.T) {
	cmd := exec.Command("go", "run", "../main.go", "help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI help failed: %v, output: %s", err, string(out))
	}
	if len(out) == 0 || string(out)[:10] != "Git Secret" {
		t.Errorf("Help output missing or incorrect: %q", string(out))
	}
}

func TestCLI_Init(t *testing.T) {
	os.RemoveAll(".gitsecret")
	cmd := exec.Command("go", "run", "../main.go", "init")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI init failed: %v, output: %s", err, string(out))
	}
	if _, err := os.Stat(".gitsecret"); err != nil {
		t.Errorf(".gitsecret dir not created")
	}
	os.RemoveAll(".gitsecret")
}
