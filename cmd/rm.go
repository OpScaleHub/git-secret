package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/OpScaleHub/git-secret/core"
)

// Rm stops tracking files for encryption.
func Rm(files []string) error {
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
	newTracked := []string{}
	removed := false
	for _, t := range tracked {
		if !contains(files, t) {
			newTracked = append(newTracked, t)
		} else {
			removed = true
		}
	}
	if removed {
		f, err := os.Create(trackedPath)
		if err != nil {
			return err
		}
		defer f.Close()
		for _, file := range newTracked {
			fmt.Fprintln(f, file)
		}
	}
	fmt.Println("Removed files from secret tracking:", strings.Join(files, ", "))
	return nil
}
