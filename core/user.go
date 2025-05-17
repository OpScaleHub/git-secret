package core

import "fmt"

// AddUserKey adds a user's key to the users file.
func AddUserKey(key string, config *Config) error {
	fmt.Printf("Adding user key: %s\n", key)
	// TODO: Implement logic to add key to users file in config.SecretDir
	return nil
}

// RemoveUserKey removes a user's key from the users file.
func RemoveUserKey(key string, config *Config) error {
	fmt.Printf("Removing user key: %s\n", key)
	// TODO: Implement logic to remove key from users file in config.SecretDir
	return nil
}

// ListUserKeys lists all user keys.
func ListUserKeys(config *Config) ([]string, error) {
	fmt.Println("Listing user keys")
	// TODO: Implement logic to list keys from users file in config.SecretDir
	return []string{}, nil
}
