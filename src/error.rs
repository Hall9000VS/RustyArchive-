use thiserror::Error;

#[derive(Debug, Error)]
pub enum RustyArchiveError {
    #[error("output file already exists. Use --overwrite to replace it.")]
    OutputAlreadyExists,
    #[error("passwords do not match.")]
    PasswordMismatch,
    #[error("decryption failed. The password may be wrong or the vault may be corrupted.")]
    DecryptionFailed,
    #[error("unsafe archive entry detected.")]
    UnsafeArchiveEntry,
    #[error("symlinks are not supported in v0.1: {0}")]
    UnsupportedSymlink(String),
    #[error("archive is too large for v0.1 in-memory mode.")]
    ArchiveTooLarge,
}
