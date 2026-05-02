use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::error::RustyArchiveError;

pub const MANIFEST_VERSION: u8 = 1;
pub const MANIFEST_ALGORITHM: &str = "sha256";
pub const MANIFEST_PATH_ENCODING: &str = "utf-8-nfc-forward-slash";
pub const MANIFEST_ARCHIVE_PATH: &str = ".rustyarchive/manifest.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u8,
    pub algorithm: String,
    pub path_encoding: String,
    pub files: Vec<ManifestEntry>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: MANIFEST_VERSION,
            algorithm: MANIFEST_ALGORITHM.to_string(),
            path_encoding: MANIFEST_PATH_ENCODING.to_string(),
            files: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSource {
    pub absolute_path: PathBuf,
    pub manifest_path: String,
    pub size: u64,
}

pub fn build_manifest(input: &Path) -> Result<Manifest> {
    let files = collect_manifest_sources(input)?;
    build_manifest_from_sources(&files)
}

pub fn collect_manifest_sources(input: &Path) -> Result<Vec<ManifestSource>> {
    let input_metadata = std::fs::symlink_metadata(input)
        .with_context(|| format!("failed to read input metadata: {}", input.display()))?;

    if input_metadata.file_type().is_symlink() {
        bail!(RustyArchiveError::UnsupportedSymlink(
            input.display().to_string()
        ));
    }

    collect_regular_files(input, &input_metadata)
}

pub fn build_manifest_from_sources(files: &[ManifestSource]) -> Result<Manifest> {
    let entries = files
        .par_iter()
        .map(|file| {
            let sha256 = sha256_file(&file.absolute_path)?;
            Ok(ManifestEntry {
                path: file.manifest_path.clone(),
                size: file.size,
                sha256,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Manifest {
        files: entries,
        ..Manifest::default()
    })
}

pub fn verify_manifest(output_dir: &Path, manifest: &Manifest) -> Result<()> {
    validate_manifest_metadata(manifest)?;

    for entry in &manifest.files {
        let relative_path = validate_manifest_path(&entry.path)?;
        let restored_path = output_dir.join(path_from_manifest_path(&relative_path));
        let metadata = std::fs::metadata(&restored_path).with_context(|| {
            format!(
                "manifest entry is missing after extraction: {}",
                relative_path
            )
        })?;

        if !metadata.is_file() {
            bail!("manifest entry is not a regular file: {relative_path}");
        }

        if metadata.len() != entry.size {
            bail!(
                "manifest size mismatch for {relative_path}: expected {}, actual {}",
                entry.size,
                metadata.len()
            );
        }

        let actual_sha256 = sha256_file(&restored_path)?;
        if actual_sha256 != entry.sha256 {
            bail!("manifest checksum mismatch for {relative_path}");
        }
    }

    Ok(())
}

pub fn validate_manifest_metadata(manifest: &Manifest) -> Result<()> {
    if manifest.version != MANIFEST_VERSION {
        bail!("unsupported manifest version: {}", manifest.version);
    }

    if manifest.algorithm != MANIFEST_ALGORITHM {
        bail!("unsupported manifest algorithm: {}", manifest.algorithm);
    }

    if manifest.path_encoding != MANIFEST_PATH_ENCODING {
        bail!(
            "unsupported manifest path encoding: {}",
            manifest.path_encoding
        );
    }

    let mut seen_paths = HashSet::new();
    for entry in &manifest.files {
        let normalized_path = validate_manifest_path(&entry.path)?;
        if !seen_paths.insert(normalized_path.clone()) {
            bail!("duplicate manifest path after normalization: {normalized_path}");
        }
    }

    Ok(())
}

pub fn validate_manifest_path(path: &str) -> Result<String> {
    if path.is_empty() {
        bail!("manifest path must not be empty");
    }

    if path.contains('\\') {
        bail!("manifest path must not contain backslash separators: {path}");
    }

    if Path::new(path).is_absolute() || path.starts_with('/') {
        bail!("manifest path must be relative: {path}");
    }

    let normalized = path.nfc().collect::<String>();
    let mut components = Vec::new();

    for component in normalized.split('/') {
        if component.is_empty() {
            bail!("manifest path contains an empty component: {path}");
        }

        if component == "." || component == ".." {
            bail!("manifest path contains an unsafe component: {path}");
        }

        if component.contains('\0') {
            bail!("manifest path contains a NUL byte: {path:?}");
        }

        if component.contains(':') {
            bail!("manifest path contains a Windows path prefix or stream marker: {path}");
        }

        if is_windows_drive_component(component) {
            bail!("manifest path contains a Windows drive component: {path}");
        }

        if is_windows_reserved_name(component) {
            bail!("manifest path contains a Windows reserved name: {path}");
        }

        components.push(component);
    }

    if components.contains(&".rustyarchive") {
        bail!("manifest path uses RustyArchive reserved metadata directory: {path}");
    }

    Ok(components.join("/"))
}

pub fn path_from_manifest_path(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn collect_regular_files(
    input: &Path,
    metadata: &std::fs::Metadata,
) -> Result<Vec<ManifestSource>> {
    let mut files = Vec::new();

    if metadata.is_file() {
        validate_regular_file_metadata(input, metadata)?;
        let file_name = input
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("input file has no file name: {}", input.display()))?;
        let manifest_path = normalize_path_components([file_name])?;
        files.push(ManifestSource {
            absolute_path: input.to_path_buf(),
            manifest_path,
            size: metadata.len(),
        });
    } else if metadata.is_dir() {
        for entry in walkdir::WalkDir::new(input).follow_links(false) {
            let entry = entry?;
            let path = entry.path();
            let entry_metadata = std::fs::symlink_metadata(path)
                .with_context(|| format!("failed to read metadata: {}", path.display()))?;
            let file_type = entry_metadata.file_type();

            if file_type.is_symlink() {
                bail!(RustyArchiveError::UnsupportedSymlink(
                    path.display().to_string()
                ));
            }

            if entry_metadata.is_dir() {
                continue;
            }

            if !entry_metadata.is_file() {
                bail!(
                    "platform-specific special files are not supported in v0.1: {}",
                    path.display()
                );
            }

            validate_regular_file_metadata(path, &entry_metadata)?;

            let relative_path = path
                .strip_prefix(input)
                .with_context(|| format!("failed to relativize path: {}", path.display()))?;
            let manifest_path = normalize_relative_path(relative_path)?;

            files.push(ManifestSource {
                absolute_path: path.to_path_buf(),
                manifest_path,
                size: entry_metadata.len(),
            });
        }
    } else {
        bail!(
            "platform-specific special files are not supported in v0.1: {}",
            input.display()
        );
    }

    files.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));

    let mut seen_paths = HashSet::new();
    for file in &files {
        if !seen_paths.insert(file.manifest_path.clone()) {
            bail!(
                "duplicate manifest path after normalization: {}",
                file.manifest_path
            );
        }
    }

    Ok(files)
}

fn normalize_relative_path(path: &Path) -> Result<String> {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            Component::Normal(value) => components.push(value),
            Component::CurDir => bail!("relative path contains current-directory component"),
            Component::ParentDir => bail!("relative path contains parent-directory component"),
            Component::RootDir | Component::Prefix(_) => bail!("relative path is not relative"),
        }
    }

    normalize_path_components(components)
}

fn normalize_path_components<'a, I>(components: I) -> Result<String>
where
    I: IntoIterator<Item = &'a std::ffi::OsStr>,
{
    let mut normalized_components = Vec::new();

    for component in components {
        let component = component
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 paths are not supported in v0.1"))?;
        normalized_components.push(component.nfc().collect::<String>());
    }

    validate_manifest_path(&normalized_components.join("/"))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open file: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read file: {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn is_windows_reserved_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let stem = stem.to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || is_numbered_windows_device(&stem, "COM")
        || is_numbered_windows_device(&stem, "LPT")
}

fn is_numbered_windows_device(stem: &str, prefix: &str) -> bool {
    let Some(suffix) = stem.strip_prefix(prefix) else {
        return false;
    };

    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
}

fn is_windows_drive_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[cfg(unix)]
fn validate_regular_file_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if metadata.nlink() > 1 {
        bail!("hard links are not supported in v0.1: {}", path.display());
    }

    Ok(())
}

#[cfg(windows)]
fn validate_regular_file_metadata(_path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_regular_file_metadata(_path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}
