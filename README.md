# Git Secret Manager (`git-secret`)

`git-secret` is a command-line tool (a Git plugin) designed to help developers manage sensitive information (secrets) securely within their Git repositories. It allows for encryption and decryption of specified files, integrating directly with Git. Encryption can be performed using GnuPG (GPG) keys or SSH keys.

## Features

- **Secure Secret Management**: Encrypts sensitive files before they are committed to Git.
- **Git Integration**: Works as a `git secret` subcommand.
- **Flexible Configuration**: Supports global (`~/.gitconfig`) and per-repository (`.git/config`) settings.
- **Multiple Encryption Backends**: Supports GPG (fully implemented) and SSH (planned) for encryption/decryption.
- **User Management**: Easily add or remove users (via their public keys or GPG IDs) who can access the secrets.
- **Cross-Platform**: Designed to work on Linux, macOS, and Windows.

## Requirements

- **Go** 1.21 or newer (for building from source)
- **Git** (for configuration and usage)
- **GPG** (for encryption/decryption; must be in your `PATH` or specify with config)
- (Optional) **SSH** (for future SSH backend support)

## Installation

You can install `git-secret` by downloading the appropriate binary for your operating system and architecture from the latest GitHub release, or by building from source.

### Download Prebuilt Binary

1.  **Download the Binary**:
    - Navigate to the [Releases](https://github.com/OpScaleHub/git-secret/releases) page.
    - Download the archive or binary for your OS and architecture (e.g., `git-secret-linux-amd64`, `git-secret-darwin-arm64`, `git-secret-windows-amd64.exe`).

2.  **Extract and Place in PATH**:
    - Extract the binary if it's in an archive.
    - Rename the binary to `git-secret` (or `git-secret.exe` for Windows).
    - Move this binary to a directory that is part of your system's `PATH`.
      - **Linux/macOS**:
        ```bash
        # Example for Linux amd64
        wget https://github.com/OpScaleHub/git-secret/releases/latest/download/git-secret-linux-amd64
        chmod +x git-secret-linux-amd64
        sudo mv git-secret-linux-amd64 /usr/local/bin/git-secret
        ```
      - **Windows**: Place `git-secret.exe` in a folder like `C:\Program Files\git-secret` and add that folder to your `PATH` environment variable, or use a directory already in your `PATH`.

3.  **Verify Installation**:
    Open a new terminal or command prompt and run:
    ```bash
    git secret help
    ```
    You should see the help message for `git-secret`.

### Build from Source

```bash
# Clone the repository
 git clone https://github.com/OpScaleHub/git-secret.git
 cd git-secret
# Build the binary
 go build -o git-secret .
# Move to a directory in your PATH
 sudo mv git-secret /usr/local/bin/
```

## Usage

Initialize secret management in your repository:
```bash
git secret init
```

Add files to be tracked for encryption:
```bash
git secret add secret.txt config.yaml
```

Add a user (by GPG key ID):
```bash
git secret adduser KEYID
```

Encrypt all tracked files:
```bash
git secret encrypt
```

Decrypt all tracked files:
```bash
git secret decrypt
```

Remove files from tracking:
```bash
git secret rm secret.txt
```

List users and tracked files:
```bash
git secret list
```

Re-encrypt all secrets (after changing users):
```bash
git secret rekey
```

For more commands and options, run:
```bash
git secret help
```

## Configuration

`git-secret` uses Git's own configuration system (`git config`). Settings can be global (in `~/.gitconfig` or `~/.config/git/config`) or local to a repository (in `.git/config`). Local settings override global ones.

**Available Configuration Options (under `[secret]` section):**

- `backend = gpg` (default) or `backend = ssh`
- `gpg_program = /usr/bin/gpg` (optional, if not in PATH)
- `ssh_command = /usr/bin/ssh` (optional, for SSH backend)
- `secret_dir = .gitsecret` (default)

Example:
```bash
git config --local secret.backend gpg
git config --local secret.gpg_program /usr/bin/gpg
git config --local secret.secret_dir .gitsecret
```

## Publishing & GitHub Pages

The project website is published at: [https://git-secret.opscale.ir](https://git-secret.opscale.ir)

To publish documentation or usage guides to GitHub Pages:

1. Ensure your documentation (e.g., this README or additional docs) is in the repository.
2. Use GitHub Actions or your preferred CI to build and deploy the site to the `gh-pages` branch.
3. In your repository settings, set GitHub Pages to use the `gh-pages` branch.
4. The site will be available at https://git-secret.opscale.ir (custom domain) or the default GitHub Pages URL.

For more details, see the [GitHub Pages documentation](https://docs.github.com/en/pages).

---

## License

MIT License. See [LICENSE](LICENSE) for details.