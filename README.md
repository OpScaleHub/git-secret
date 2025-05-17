# Git Secret Manager (`git-secret`)

`git-secret` is a command-line tool (a Git plugin) designed to help developers manage sensitive information (secrets) securely within their Git repositories. It allows for encryption and decryption of specified files, integrating directly with Git. Encryption can be performed using GnuPG (GPG) keys or SSH keys.

## Features

*   **Secure Secret Management**: Encrypts sensitive files before they are committed to Git.
*   **Git Integration**: Works as a `git secret` subcommand.
*   **Flexible Configuration**: Supports global (`~/.gitconfig`) and per-repository (`.git/config`) settings.
*   **Multiple Encryption Backends**: Supports GPG and SSH for encryption/decryption.
*   **User Management**: Easily add or remove users (via their public keys or GPG IDs) who can access the secrets.
*   **Cross-Platform**: Designed to work on Linux, macOS, and Windows.

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

*   `backend`: The encryption backend to use.
    *   Values: `"gpg"` (default) or `"ssh"`.
    *   Example: `git config --global secret.backend ssh`
*   `gpg_program`: (Optional) Path to the GPG executable if not in `PATH`.
    *   Example: `git config --global secret.gpg_program /usr/local/bin/gpg`
*   `ssh_command`: (Optional) Path to the SSH command (primarily for key operations if needed, actual crypto might use `openssl`).
    *   Example: `git config --global secret.ssh_command /usr/bin/ssh`
*   `secret_dir`: The directory within the repository to store `git-secret`'s internal files (like user keyrings and tracked file lists).
    *   Default: `.gitsecret`
    *   Example: `git config secret.secret_dir .repo-secrets`

**Example Global Configuration (`~/.gitconfig`):**
```toml
[secret]
    backend = "gpg"
    secret_dir = ".gitsecret"
```

**Example Per-Repository Configuration (`.git/config`):**
```toml
[secret]
    backend = "ssh"
    secret_dir = ".mysecrets" # Overrides global and default
```

## Core Workflow & Commands

Here's how you typically use `git-secret`:

### 1. Initialize `git-secret` in Your Repository
This is the first step for any repository where you want to manage secrets.

```bash
git secret init
```
This command:
*   Creates the secret directory (e.g., `.gitsecret/`) if it doesn't exist. This directory will store `git-secret`'s metadata, such as the list of authorized users and tracked files. This directory **should be committed** to your repository.
*   Creates a `users` file (e.g., `.gitsecret/users`) to store GPG user IDs or SSH public keys of individuals authorized to decrypt the secrets.
*   It should also prepare or guide you to update the repository's `.gitignore` file to ensure that *unencrypted versions* of your secret files are not accidentally committed.

### 2. Add Users (Collaborators)
To allow other users (or yourself on different machines) to decrypt secrets, you must add their GPG User ID or their SSH public key.

**Using GPG:**
```bash
# Add a user by their GPG User ID (e.g., email address associated with the GPG key)
git secret adduser "User Name <user@example.com>"
git secret adduser "another_gpg_key_id"
```
The GPG public key corresponding to the ID must be in your local GPG keyring. `git-secret` will use this ID to find the public key for encryption.

**Using SSH:**
First, ensure your `secret.backend` is set to `ssh`.
```bash
git config secret.backend ssh
```
Then, add a user's SSH public key:
```bash
# Add a user by providing their actual SSH public key string
git secret adduser "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD..."
# Or, if the key is in a file:
git secret adduser "$(cat ~/.ssh/id_rsa.pub)"
```

After adding users, commit the changes to the `.gitsecret/` directory (specifically the `users` file) to share the updated access list with collaborators.
```bash
git add .gitsecret/
git commit -m "Add new user to git-secret"
```

### 3. Add Files to be Encrypted
Tell `git-secret` which files contain sensitive information.

```bash
git secret add path/to/your/secretfile.yml another/secret.json
```
This command:
*   Records the specified file(s) in a list within the `.gitsecret/` directory.
*   **Crucially, it should also add the original unencrypted file paths (e.g., `path/to/your/secretfile.yml`) to your repository's `.gitignore` file.** This prevents the unencrypted version from ever being committed.

After adding files, commit the changes to the `.gitsecret/` directory (for the tracked files list) and the `.gitignore` file.
```bash
git add .gitsecret/ .gitignore
git commit -m "Track new secret files with git-secret"
```

### 4. Encrypt Your Secrets
Once files are added and users are configured, you can encrypt them.

```bash
git secret encrypt
```
This command:
*   Finds all files tracked by `git-secret`.
*   For each file, it encrypts its content using the public keys/GPG IDs of all users added via `git secret adduser`.
*   The encrypted version of the file will be created (e.g., `path/to/your/secretfile.yml.secret` or potentially stored within the `.gitsecret` directory, depending on implementation, like `.gitsecret/encrypted/path/to/your/secretfile.yml.secret`).
*   The original unencrypted file should remain gitignored and not part of the commit.

Now, add the newly encrypted files to your Git staging area and commit them:
```bash
# Example: if encrypted files are named like original.ext.secret in their original location
git add path/to/your/secretfile.yml.secret another/secret.json.secret
git commit -m "Add encrypted secrets"
```
Your unencrypted files remain local (and gitignored), while their encrypted versions are safe to push to your remote repository.

### 5. Decrypting Secrets
When you or a collaborator pulls the repository, the secret files will be in their encrypted state. To decrypt them:

```bash
git secret decrypt
```
This command:
*   Finds all encrypted files tracked by `git-secret`.
*   Attempts to decrypt them using the private key (GPG or SSH) corresponding to one of the authorized users.
    *   For GPG, you'll need your GPG private key in your keyring and potentially enter your passphrase.
    *   For SSH, you'll need your SSH private key, possibly loaded into `ssh-agent`.
*   The decrypted content will be placed back into the original file paths (e.g., `path/to/your/secretfile.yml`). These files are gitignored.

**Important:** Decrypted files are intended for local use only and should **never** be committed. The `.gitignore` rules are meant to prevent this.

### Other Useful Commands

*   **`git secret list`**:
    Lists all users currently authorized to decrypt secrets and all files currently tracked for encryption.

*   **`git secret rm <file(s)>`**:
    Stops tracking the specified file(s) for encryption. You'll need to manually remove the encrypted file from git and potentially update `.gitignore`.

*   **`git secret removeuser <key>`**:
    Removes a user's key (GPG ID or SSH public key string). **Remember to run `git secret rekey` afterwards.**

*   **`git secret rekey`**:
    Re-encrypts all currently tracked secret files. Essential after adding/removing users to ensure correct access.

*   **`git secret help`**:
    Displays help information and a list of commands.

## Advanced Usage & Best Practices

*   **Initial Setup Workflow**:
    1.  `git secret init`
    2.  `git secret adduser "your_gpg_id_or_ssh_pubkey"` (add yourself first)
    3.  `git add .gitsecret/`
    4.  `git commit -m "Initialize git-secret and add initial user"`
    5.  Push to remote.

*   **Adding a New Secret File**:
    1.  Create your secret file (e.g., `config/credentials.json`).
    2.  `git secret add config/credentials.json` (this should update `.gitignore`)
    3.  `git secret encrypt`
    4.  `git add .gitignore .gitsecret/` (if `paths` file changed)
    5.  `git add path/to/encrypted/file.ext.secret`
    6.  `git commit -m "Add and encrypt new credentials file"`
    7.  Push.

*   **Collaborator Onboarding**:
    1.  New collaborator provides their GPG ID or SSH public key.
    2.  An existing authorized user runs `git secret adduser "new_user_key"`.
    3.  `git secret rekey` (to allow the new user to decrypt existing secrets).
    4.  `git add .gitsecret/` (for updated user list)
    5.  `git add path/to/all/re-encrypted-files*.secret`
    6.  `git commit -m "Add new user and rekey secrets"`
    7.  Push.
    8.  New collaborator pulls, then runs `git secret decrypt`.

*   **Security Considerations**:
    *   **Private Key Management**: `git-secret` **does not** manage your private GPG or SSH keys. You are responsible for their security.
    *   **`.gitignore` is Crucial**: Ensure your unencrypted secret files are correctly gitignored.
    *   **Audit User List**: Regularly run `git secret list`.
    *   **Rekey After Removing Users**: Always run `git secret rekey` immediately after `git secret removeuser` and commit the changes.

*   **Choosing a Backend (GPG vs. SSH)**:
    *   **GPG**: Well-established, supports complex trust models. Requires GPG installed.
    *   **SSH**: SSH keys are ubiquitous. Security depends on the chosen encryption method (e.g., using `openssl` with a symmetric key encrypted asymmetrically with each SSH public key).

## Troubleshooting

*   **"Decryption failed"**:
    *   Ensure your GPG/SSH private key is available (e.g., GPG agent, `ssh-agent`).
    *   Verify you were added as a user (`git secret list`).
    *   If a new user was added, ensure `git secret rekey` was run and you have pulled the latest changes.
*   **"Command not found: git-secret"**:
    *   Verify the `git-secret` binary is in your `PATH` and is executable.

## Contributing

We welcome contributions! Please refer to `CONTRIBUTING.md` (to be created) for guidelines on how to:
*   Report bugs and suggest features.
*   Submit pull requests.
*   Build the project from source.
*   Run tests.

## License

This project is licensed under the MIT License.
(You'll need to add a `LICENSE` file with the MIT License text, or your chosen license).