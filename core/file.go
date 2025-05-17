package core

import (
	"bufio"
	"os"
	"strings"
)

// CreateSecretDir creates the secret directory if it doesn't exist.
func CreateSecretDir(path string) error {
	return os.MkdirAll(path, 0o700)
}

// UpdateGitIgnore adds necessary entries to .gitignore.
func UpdateGitIgnore(secretDir string) error {
	ignorePath := ".gitignore"
	entries := []string{secretDir + "/", "*.secret"}
	return updateGitIgnoreWithEntries(ignorePath, entries)
}

// UpdateGitIgnoreEntry adds a single file entry to the specified ignore file if missing.
func UpdateGitIgnoreEntry(ignorePath, file string) error {
	var lines []string
	if data, err := os.ReadFile(ignorePath); err == nil {
		lines = strings.Split(string(data), "\n")
	}
	for _, l := range lines {
		if l == file {
			return nil // Already present
		}
	}
	f, err := os.OpenFile(ignorePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(file + "\n")
	return err
}

func updateGitIgnoreWithEntries(ignorePath string, entries []string) error {
	var lines []string
	if data, err := os.ReadFile(ignorePath); err == nil {
		lines = strings.Split(string(data), "\n")
	}
	changed := false
	for _, entry := range entries {
		if entry == "" {
			continue
		}
		if !containsLine(lines, entry) {
			lines = append(lines, entry)
			changed = true
		}
	}
	if changed {
		return os.WriteFile(ignorePath, []byte(joinLines(lines)), 0o644)
	}
	return nil
}

func containsLine(lines []string, entry string) bool {
	for _, l := range lines {
		if l == entry {
			return true
		}
	}
	return false
}

func joinLines(lines []string) string {
	result := ""
	for _, l := range lines {
		if l != "" && l[len(l)-1] != '\n' {
			result += l + "\n"
		} else {
			result += l
		}
	}
	return result
}

// ListTrackedFiles lists all files tracked for encryption.
func ListTrackedFiles(config *Config) ([]string, error) {
	trackedPath := config.SecretDir + "/tracked"
	var files []string
	f, err := os.Open(trackedPath)
	if err != nil {
		return files, nil // If not found, treat as empty
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		files = append(files, scanner.Text())
	}
	return files, nil
}
