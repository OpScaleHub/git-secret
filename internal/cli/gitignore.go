package cli

import (
	"os"
	"path/filepath"
	"strings"
)

// ensureGitignored appends entry to repoRoot/.gitignore if it isn't
// already covered by an identical line. Used to make sure a locally
// stored key file is never accidentally committed.
func ensureGitignored(repoRoot, entry string) error {
	path := filepath.Join(repoRoot, ".gitignore")
	entry = filepath.ToSlash(entry)

	var lines []string
	if data, err := os.ReadFile(path); err == nil {
		lines = strings.Split(string(data), "\n")
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, l := range lines {
		if strings.TrimSpace(l) == entry {
			return nil
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(entry + "\n")
	return err
}
