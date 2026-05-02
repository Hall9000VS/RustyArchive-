use thiserror::Error;

#[derive(Debug, Error)]
pub enum RustyArchiveError {
    #[error("output path already exists. Use --overwrite only when the target semantics allow it.")]
    OutputAlreadyExists,
    #[error("output directory is not empty. Choose an empty directory for extraction.")]
    OutputDirectoryNotEmpty,
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
