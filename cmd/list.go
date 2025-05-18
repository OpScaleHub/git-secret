package cmd

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/core"
)

// List lists users and encrypted files.
func List() error {
	config, err := core.LoadConfig()
	if err != nil {
		return err
	}
	users, err := core.ListUserKeys(config)
	if err != nil {
		return err
	}
	fmt.Println("Users:")
	for _, u := range users {
		fmt.Println("  ", u)
	}
	files, err := core.ListTrackedFiles(config)
	if err != nil {
		return err
	}
	fmt.Println("Tracked files:")
	for _, f := range files {
		fmt.Println("  ", f)
	}
	return nil
}
