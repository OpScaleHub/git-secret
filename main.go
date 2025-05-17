package main

import (
	"fmt"
	"os"

	"github.com/OpScaleHub/git-secret/cmd"
	// Adjust the import path above based on your actual module path
	// e.g., "yourusername/git-secret/cmd"
	// You'll need to run `go mod init yourusername/git-secret` in the project root.
)

func main() {
	if len(os.Args) < 2 {
		cmd.Help()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error

	switch command {
	case "init":
		err = cmd.Init()
	case "add":
		if len(args) == 0 {
			fmt.Println("Error: 'add' command requires at least one file argument.")
			cmd.Help()
			os.Exit(1)
		}
		err = cmd.Add(args)
	case "rm":
		if len(args) == 0 {
			fmt.Println("Error: 'rm' command requires at least one file argument.")
			cmd.Help()
			os.Exit(1)
		}
		err = cmd.Rm(args)
	case "encrypt":
		err = cmd.Encrypt()
	case "decrypt":
		err = cmd.Decrypt()
	case "adduser":
		if len(args) != 1 {
			fmt.Println("Error: 'adduser' command requires exactly one key argument.")
			cmd.Help()
			os.Exit(1)
		}
		err = cmd.AddUser(args[0])
	case "removeuser":
		if len(args) != 1 {
			fmt.Println("Error: 'removeuser' command requires exactly one key argument.")
			cmd.Help()
			os.Exit(1)
		}
		err = cmd.RemoveUser(args[0])
	case "list":
		err = cmd.List()
	case "rekey":
		err = cmd.Rekey()
	case "help":
		cmd.Help()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		cmd.Help()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
