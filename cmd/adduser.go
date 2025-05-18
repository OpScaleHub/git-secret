package cmd

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/core"
)

// AddUser adds a user's key.
func AddUser(key string) error {
	config, err := core.LoadConfig()
	if err != nil {
		return err
	}
	if err := core.AddUserKey(key, config); err != nil {
		return err
	}
	fmt.Println("Added user:", key)
	return nil
}
