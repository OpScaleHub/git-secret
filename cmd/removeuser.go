package cmd

import (
	"fmt"

	"github.com/OpScaleHub/git-secret/core"
)

// RemoveUser removes a user's key.
func RemoveUser(key string) error {
	config, err := core.LoadConfig()
	if err != nil {
		return err
	}
	if err := core.RemoveUserKey(key, config); err != nil {
		return err
	}
	fmt.Println("Removed user:", key)
	return nil
}
