# RustyArchive

RustyArchive is a Rust CLI vault tool that compresses files or folders and encrypts the resulting archive with a password-derived key.

## Status

This repository contains the RustyArchive v0.1 MVP implementation.

## Usage

Pack a folder into an encrypted vault:

```bash
rustyarchive pack ./my-folder -o backup.rav
```

Restore a vault:

```bash
rustyarchive unpack backup.rav -o ./restored
```

Inspect unauthenticated header metadata:

```bash
rustyarchive info backup.rav
```

Use `--overwrite` when replacing an existing vault or extracting into an existing directory.

## Features

- Pack files and folders into encrypted `.rav` vaults
- Restore vaults with password-based decryption
- Argon2id password-based key derivation
- XChaCha20-Poly1305 authenticated encryption
- Byte-exact authenticated vault header metadata
- ZIP-based folder archiving
- Mandatory manifest with SHA-256 checksums
- Safe extraction with conservative path validation
- Explicit symlink rejection
- Atomic vault output writes via temporary file and rename

## Current Limitations

- The archive payload remains in memory in v0.1.
- Archives above approximately 1 GB are rejected in v0.1.
- Symlinks are rejected in v0.1.
- Empty directories are not preserved in v0.1.
- File permissions, ACLs, owners, timestamps, xattrs, and hard-link relationships are not preserved.
- This project is not a replacement for a professionally audited backup system.

## Development

```bash
cargo check
cargo test
cargo clippy --all-targets --all-features
```
