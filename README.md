# Git Secret Manager (`git-secret`)

`git-secret` is a command-line tool (a Git plugin) designed to help developers manage sensitive information (secrets) securely within their Git repositories. It allows for encryption and decryption of specified files, integrating directly with Git. Encryption can be performed using GnuPG (GPG) keys or SSH keys.

## Features

- **Secure Secret Management**: Encrypts sensitive files before they are committed to Git.
- **Git Integration**: Works as a `git secret` subcommand.
- **Flexible Configuration**: Supports global (`~/.gitconfig`) and per-repository (`.git/config`) settings.
- **Multiple Encryption Backends**: Supports GPG (fully implemented) and SSH (planned) for encryption/decryption.
- **User Management**: Easily add or remove users (via their public keys or GPG IDs) who can access the secrets.
- **Cross-Platform**: Designed to work on Linux, macOS, and Windows.

## Installation

You can install `git-secret` by downloading the appropriate binary for your operating system and architecture from our latest GitHub release.

1.  **Download the Binary**:
    *   Navigate to the Releases page.
    *   Download the archive or binary corresponding to your OS and architecture (e.g., `git-secret-linux-amd64`, `git-secret-darwin-arm64`, `git-secret-windows-amd64.exe`).

2.  **Extract and Place in PATH**:
    *   Extract the binary if it's in an archive.
    *   Rename the binary to `git-secret` (or `git-secret.exe` for Windows).
    *   Move this binary to a directory that is part of your system's `PATH`.
        *   **Linux/macOS**: A common location is `/usr/local/bin/`.
          ```bash
          # Example for Linux amd64 (assuming you downloaded the binary directly)
          # wget https://github.com/OpScaleHub/git-secret/releases/latest/download/git-secret-linux-amd64
          # chmod +x git-secret-linux-amd64
          # sudo mv git-secret-linux-amd64 /usr/local/bin/git-secret
          ```
        *   **Windows**: You can place `git-secret.exe` in a folder like `C:\Program Files\git-secret` and add that folder to your `PATH` environment variable, or use a directory already in your `PATH`.

3.  **Verify Installation**:
    Open a new terminal or command prompt and run:
    ```bash
    git secret help
    ```
    You should see the help message for `git-secret`.

## Configuration

`git-secret` uses Git's own configuration system (`git config`). Settings can be global (in `~/.gitconfig` or `~/.config/git/config`) or local to a repository (in `.git/config`). Local settings override global ones.

**Available Configuration Options (under `[secret]` section):**

- `backend = gpg` (default) or `backend = ssh` (no quotes, no TOML syntax)
- `gpg_program = /usr/bin/gpg` (optional, if not in PATH)
- `ssh_command = /usr/bin/ssh` (optional, for SSH backend)
- `secret_dir = .gitsecret` (default)

**Example Global Configuration (`~/.gitconfig`):**

```
[secret]
	backend = gpg
	secret_dir = .gitsecret
```

**Example Per-Repository Configuration (`.git/config`):**

```
[secret]
	backend = ssh
	secret_dir = .mysecrets
```

> **Note:** Do not use quotes or TOML-style syntax in your git config files. Only use the format shown above.

## Core Workflow & Commands

Here's how you typically use `git-secret`:

### 1. Initialize `git-secret` in Your Repository
This is the first step for any repository where you want to manage secrets.

```sh
git secret init
```

- Creates the secret directory (e.g., `.gitsecret/`) if it doesn't exist.
- Creates a `users` file (e.g., `.gitsecret/users`) to store GPG user IDs or SSH public keys.
- Updates the repository's `.gitignore` file to ensure that unencrypted secret files are not accidentally committed.

### 2. Add Users (Collaborators)
To allow other users (or yourself on different machines) to decrypt secrets, you must add their GPG User ID or their SSH public key.

**Using GPG:**

```sh
git secret adduser "User Name <user@example.com>"
```

The GPG public key corresponding to the ID must be in your local GPG keyring. `git-secret` will use this ID to find the public key for encryption.

**Using SSH:**
First, ensure your `secret.backend` is set to `ssh`.

```sh
git config secret.backend ssh
```

Then, add a user's SSH public key:

```sh
git secret adduser "ssh-ed25519 AAAA... user@host"
```

After adding users, commit the changes to the `.gitsecret/` directory (specifically the `users` file) to share the updated access list with collaborators.

```sh
git add .gitsecret/
git commit -m "Add new user to git-secret"
```

### 3. Add Files to be Encrypted
Tell `git-secret` which files contain sensitive information.

```sh
git secret add path/to/your/secretfile.yml another/secret.json
```

- Tracks the specified files for encryption.
- Adds the original unencrypted file paths to your repository's `.gitignore` file.

### 4. Encrypt Your Secrets
Once files are added and users are configured, you can encrypt them.

```sh
git secret encrypt
```

- Encrypts all tracked files using the public keys/GPG IDs of all users added via `git secret adduser`.
- The encrypted version of the file will be created as `file.secret`.
- **Note:** Only the GPG backend is currently implemented. SSH backend is planned.

### 5. Decrypting Secrets
When you or a collaborator pulls the repository, the secret files will be in their encrypted state. To decrypt them:

```sh
git secret decrypt
```

- Decrypts all `.secret` files back to their original file paths.
- Requires your GPG private key in your keyring (for GPG backend).

### Other Useful Commands

- `git secret list`: Lists all users and tracked files.
- `git secret rm <file(s)>`: Stops tracking the specified file(s) for encryption.
- `git secret removeuser <key>`: Removes a user's key.
- `git secret rekey`: Re-encrypts all currently tracked secret files (after adding/removing users).
- `git secret help`: Displays help information and a list of commands.

## Troubleshooting

- **GPG encryption failed**: Make sure the GPG key you added with `adduser` is present in your local keyring and is a GPG key (not an SSH key) if using the GPG backend.
- **Config errors**: Ensure your `[secret]` section in `.gitconfig` or `.git/config` does not use quotes or TOML syntax.

## License

MIT License.