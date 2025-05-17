package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/OpScaleHub/git-secret/core"
)

// Add tracks files for encryption.
func Add(files []string) error {
	config, err := core.LoadConfig()
	if err != nil {
		return err
	}
	trackedPath := filepath.Join(config.SecretDir, "tracked")
	var tracked []string
	if f, err := os.Open(trackedPath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			tracked = append(tracked, scanner.Text())
		}
		f.Close()
	}
	added := false
	for _, file := range files {
		if !contains(tracked, file) {
			tracked = append(tracked, file)
			added = true
		}
	}
	if added {
		f, err := os.Create(trackedPath)
		if err != nil {
			return err
		}
		defer f.Close()
		for _, file := range tracked {
			fmt.Fprintln(f, file)
		}
	}
	// Update .gitignore for each file
	for _, file := range files {
		core.UpdateGitIgnoreEntry(file)
	}
	fmt.Println("Added files to secret tracking:", strings.Join(files, ", "))
	return nil
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}
