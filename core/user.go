package core

import (
	"bufio"
	"os"
	"strings"
)

// AddUserKey adds a user's key to the users file.
func AddUserKey(key string, config *Config) error {
	usersPath := config.SecretDir + "/users"
	key = strings.TrimSpace(key)
	var users []string
	f, err := os.Open(usersPath)
	if err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				users = append(users, line)
			}
		}
		f.Close()
	}
	for _, u := range users {
		if u == key {
			return nil // Already present
		}
	}
	f, err = os.OpenFile(usersPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(key + "\n")
	return err
}

// RemoveUserKey removes a user's key from the users file.
func RemoveUserKey(key string, config *Config) error {
	usersPath := config.SecretDir + "/users"
	var users []string
	f, err := os.Open(usersPath)
	if err != nil {
		return nil // Nothing to remove
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		u := scanner.Text()
		if u != key {
			users = append(users, u)
		}
	}
	f.Close()
	f, err = os.Create(usersPath)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, u := range users {
		f.WriteString(u + "\n")
	}
	return nil
}

// ListUserKeys lists all user keys.
func ListUserKeys(config *Config) ([]string, error) {
	usersPath := config.SecretDir + "/users"
	var users []string
	f, err := os.Open(usersPath)
	if err != nil {
		return users, nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		users = append(users, scanner.Text())
	}
	return users, nil
}
