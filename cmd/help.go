package cmd

import "fmt"

// Help displays help information.
func Help() {
	fmt.Println("Git Secret Manager - Help")
	// TODO: Implement detailed help messages for each command
	fmt.Println(`
Usage: git secret <command> [options]

Commands:
  init          Initializes the secret management system for the current repository.
  add <file(s)> Adds files to be tracked for encryption.
  rm <file(s)>  Removes files from the list of files to be tracked/encrypted.
  encrypt       Encrypts all files currently tracked for encryption.
  decrypt       Decrypts all encrypted files in the repository.
  adduser <key> Adds a user's key (SSH public key or GPG ID) to the users file.
  removeuser <key> Removes a user's key.
  list          Lists all users and encrypted files.
  rekey         Re-encrypts all secrets with the current set of users.
  help          Displays help information.
`)
}
