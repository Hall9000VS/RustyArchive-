use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::cli::{InfoArgs, PackArgs, UnpackArgs};
use crate::crypto::{
    CryptoParams, KdfParams, decrypt_payload, encrypt_payload_with_params, generate_crypto_params,
};
use crate::manifest::{
    MANIFEST_ARCHIVE_PATH, Manifest, build_manifest, path_from_manifest_path,
    validate_manifest_metadata, validate_manifest_path, verify_manifest,
};
use crate::vault_format::{
    COMPRESSION_ZIP, ENCRYPTION_XCHACHA20_POLY1305, FIXED_V1_HEADER_LENGTH, FORMAT_VERSION,
    KDF_ARGON2ID, MAX_V0_1_CIPHERTEXT_LENGTH, VaultHeader, parse_header, parse_header_from_file,
    serialize_header,
};

pub const MAX_V0_1_ARCHIVE_BYTES: u64 = 1_073_741_824;

pub fn pack(args: PackArgs) -> Result<()> {
    let mut password = prompt_new_password()?;
    let result = pack_with_password(args, &password);
    password.zeroize();
    result
}

pub fn unpack(args: UnpackArgs) -> Result<()> {
    let mut password = rpassword::prompt_password("Vault password: ")?;
    let result = unpack_with_password(args, &password);
    password.zeroize();
    result
}

pub fn info(args: InfoArgs) -> Result<()> {
    let mut file = File::open(&args.input)?;
    let mut header_bytes = vec![0u8; FIXED_V1_HEADER_LENGTH as usize];
    file.read_exact(&mut header_bytes)?;

    let header = parse_header(&header_bytes)?;
    println!("{}", render_vault_info(&header));

    Ok(())
}

pub fn create_zip_payload(input: &Path, manifest: &Manifest) -> Result<Vec<u8>> {
    validate_manifest_metadata(manifest)?;
    ensure_manifest_size_within_v0_1_limit(manifest)?;

    let cursor = Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for entry in &manifest.files {
        let manifest_path = validate_manifest_path(&entry.path)?;
        let source_path = source_path_for_manifest_entry(input, &manifest_path)?;
        let metadata = std::fs::metadata(&source_path).with_context(|| {
            format!(
                "failed to read source file metadata: {}",
                source_path.display()
            )
        })?;

        if !metadata.is_file() {
            bail!(
                "manifest source is not a regular file: {}",
                source_path.display()
            );
        }

        if metadata.len() != entry.size {
            bail!(
                "source file size changed while packing: {}",
                source_path.display()
            );
        }

        zip.start_file(&manifest_path, options)?;
        let mut source_file = File::open(&source_path)
            .with_context(|| format!("failed to open source file: {}", source_path.display()))?;
        std::io::copy(&mut source_file, &mut zip)
            .with_context(|| format!("failed to write ZIP entry: {manifest_path}"))?;
    }

    zip.start_file(MANIFEST_ARCHIVE_PATH, options)?;
    let manifest_json = serde_json::to_vec_pretty(manifest)?;
    zip.write_all(&manifest_json)?;

    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

pub fn extract_zip_payload(payload: &[u8], output_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "failed to create output directory: {}",
            output_dir.display()
        )
    })?;
    let base = output_dir.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize output directory: {}",
            output_dir.display()
        )
    })?;

    let cursor = Cursor::new(payload);
    let mut zip = zip::ZipArchive::new(cursor)?;
    let manifest = read_manifest_from_zip(&mut zip)?;
    validate_manifest_metadata(&manifest)?;
    let expected_files = manifest
        .files
        .iter()
        .map(|entry| validate_manifest_path(&entry.path))
        .collect::<Result<HashSet<_>>>()?;

    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        let entry_name = entry.name().to_string();

        if entry_name == MANIFEST_ARCHIVE_PATH {
            continue;
        }

        let is_directory = entry.is_dir();
        let validated_path = validate_zip_entry_path(&entry_name, is_directory)?;

        if is_zip_symlink(&entry) {
            bail!("symlinks are not supported in v0.1: {validated_path}");
        }

        if is_directory {
            continue;
        }

        if !expected_files.contains(&validated_path) {
            bail!("ZIP entry is not listed in the manifest: {validated_path}");
        }

        let relative_path = path_from_manifest_path(&validated_path);
        let target = base.join(relative_path);
        let parent = target
            .parent()
            .ok_or_else(|| anyhow::anyhow!("ZIP entry has no parent: {validated_path}"))?;
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create extraction directory: {}",
                parent.display()
            )
        })?;
        reject_symlink_ancestors(&base, parent)?;
        let parent_canonical = parent.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize extraction directory: {}",
                parent.display()
            )
        })?;

        if !parent_canonical.starts_with(&base) {
            bail!("unsafe archive entry detected: {validated_path}");
        }

        let mut output_file = File::create(&target)
            .with_context(|| format!("failed to create extracted file: {}", target.display()))?;
        std::io::copy(&mut entry, &mut output_file)
            .with_context(|| format!("failed to extract ZIP entry: {validated_path}"))?;
    }

    verify_manifest(&base, &manifest)?;
    Ok(())
}

pub fn pack_with_password(args: PackArgs, password: &str) -> Result<()> {
    let _ = args.no_progress;
    validate_pack_output(&args.output, args.overwrite)?;

    let manifest = build_manifest(&args.input)?;
    let zip_payload = create_zip_payload(&args.input, &manifest)?;
    if zip_payload.len() as u64 > MAX_V0_1_ARCHIVE_BYTES {
        bail!("archive is too large for v0.1 in-memory mode");
    }

    let crypto_params = generate_crypto_params(KdfParams::default());
    let header = header_for_crypto_params(&crypto_params, zip_payload.len() as u64 + 16)?;
    let header_bytes = serialize_header(&header)?;
    let encrypted_payload =
        encrypt_payload_with_params(password, &zip_payload, &header_bytes, crypto_params)?;

    if encrypted_payload.ciphertext.len() as u64 != header.ciphertext_length {
        bail!("internal ciphertext length mismatch while packing");
    }

    let mut vault_bytes =
        Vec::with_capacity(header_bytes.len() + encrypted_payload.ciphertext.len());
    vault_bytes.extend_from_slice(&header_bytes);
    vault_bytes.extend_from_slice(&encrypted_payload.ciphertext);
    write_file_atomically(&args.output, &vault_bytes, args.overwrite)?;

    Ok(())
}

pub fn unpack_with_password(args: UnpackArgs, password: &str) -> Result<()> {
    let _ = args.no_progress;
    validate_unpack_output(&args.output, args.overwrite)?;

    let vault_bytes = fs::read(&args.input)
        .with_context(|| format!("failed to read vault file: {}", args.input.display()))?;
    let header = parse_header_from_file(&vault_bytes)?;
    let header_bytes = serialize_header(&header)?;
    let ciphertext = &vault_bytes[FIXED_V1_HEADER_LENGTH as usize..];
    let crypto_params = CryptoParams {
        kdf: header.kdf_params,
        salt: header.salt.to_vec(),
        nonce: header.nonce.to_vec(),
    };
    let zip_payload = decrypt_payload(password, &crypto_params, ciphertext, &header_bytes)?;
    extract_zip_payload(&zip_payload, &args.output)?;

    Ok(())
}

fn prompt_new_password() -> Result<String> {
    let password = rpassword::prompt_password("Vault password: ")?;
    let mut confirmation = rpassword::prompt_password("Confirm vault password: ")?;

    if password != confirmation {
        confirmation.zeroize();
        bail!("passwords do not match");
    }

    confirmation.zeroize();
    Ok(password)
}

fn header_for_crypto_params(params: &CryptoParams, ciphertext_length: u64) -> Result<VaultHeader> {
    if ciphertext_length > MAX_V0_1_CIPHERTEXT_LENGTH {
        bail!("ciphertext length exceeds the v0.1 maximum");
    }

    let mut salt = [0u8; crate::vault_format::SALT_LENGTH];
    salt.copy_from_slice(&params.salt);
    let mut nonce = [0u8; crate::vault_format::XCHACHA20POLY1305_NONCE_LENGTH];
    nonce.copy_from_slice(&params.nonce);

    Ok(VaultHeader {
        format_version: FORMAT_VERSION,
        compression: COMPRESSION_ZIP,
        kdf: KDF_ARGON2ID,
        kdf_params: params.kdf,
        encryption: ENCRYPTION_XCHACHA20_POLY1305,
        ciphertext_length,
        salt,
        nonce,
    })
}

fn validate_pack_output(output: &Path, overwrite: bool) -> Result<()> {
    if output.exists() && !overwrite {
        bail!("output file already exists. Use --overwrite to replace it.");
    }

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory: {}", parent.display()))?;
    }

    Ok(())
}

fn validate_unpack_output(output: &Path, overwrite: bool) -> Result<()> {
    if output.exists() && !overwrite {
        bail!("output directory already exists. Use --overwrite to extract into it.");
    }

    if output.exists() && !output.is_dir() {
        bail!("unpack output path exists and is not a directory");
    }

    Ok(())
}

fn write_file_atomically(output: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let temp_path = temporary_output_path(output);
    {
        let mut temp_file = File::create(&temp_path).with_context(|| {
            format!("failed to create temporary vault: {}", temp_path.display())
        })?;
        temp_file.write_all(bytes)?;
        temp_file.sync_all()?;
    }

    if overwrite && output.exists() {
        fs::remove_file(output)
            .with_context(|| format!("failed to replace existing vault: {}", output.display()))?;
    }

    fs::rename(&temp_path, output)
        .with_context(|| {
            format!(
                "failed to move temporary vault into place: {}",
                output.display()
            )
        })
        .inspect_err(|_| {
            let _ = fs::remove_file(&temp_path);
        })?;

    Ok(())
}

fn temporary_output_path(output: &Path) -> PathBuf {
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let random = u64::from_le_bytes(random);
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.rav");
    output.with_file_name(format!("{file_name}.{random:016x}.tmp"))
}

fn ensure_manifest_size_within_v0_1_limit(manifest: &Manifest) -> Result<()> {
    let total_size = manifest
        .files
        .iter()
        .try_fold(0u64, |total, entry| total.checked_add(entry.size))
        .ok_or_else(|| anyhow::anyhow!("archive size overflow"))?;

    if total_size > MAX_V0_1_ARCHIVE_BYTES {
        bail!("archive is too large for v0.1 in-memory mode");
    }

    Ok(())
}

fn source_path_for_manifest_entry(input: &Path, manifest_path: &str) -> Result<PathBuf> {
    let metadata = std::fs::metadata(input)
        .with_context(|| format!("failed to read input metadata: {}", input.display()))?;

    if metadata.is_file() {
        let file_name = input
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("input file has no file name: {}", input.display()))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 paths are not supported in v0.1"))?;
        if validate_manifest_path(file_name)? != manifest_path {
            bail!("manifest path does not match input file name: {manifest_path}");
        }
        Ok(input.to_path_buf())
    } else {
        Ok(input.join(path_from_manifest_path(manifest_path)))
    }
}

fn read_manifest_from_zip<R: Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
) -> Result<Manifest> {
    let mut manifest_file = zip
        .by_name(MANIFEST_ARCHIVE_PATH)
        .context("ZIP payload does not contain the required RustyArchive manifest")?;

    if is_zip_symlink(&manifest_file) {
        bail!("manifest entry must not be a symlink");
    }

    let mut manifest_json = String::new();
    manifest_file.read_to_string(&mut manifest_json)?;
    let manifest = serde_json::from_str(&manifest_json)?;
    Ok(manifest)
}

fn validate_zip_entry_path(path: &str, is_directory: bool) -> Result<String> {
    if path == MANIFEST_ARCHIVE_PATH {
        return Ok(path.to_string());
    }

    let path = if is_directory {
        path.trim_end_matches('/')
    } else {
        path
    };

    validate_manifest_path(path)
}

fn is_zip_symlink<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> bool {
    entry
        .unix_mode()
        .is_some_and(|mode| (mode & 0o170000) == 0o120000)
}

fn reject_symlink_ancestors(base: &Path, parent: &Path) -> Result<()> {
    let relative_parent = parent.strip_prefix(base).with_context(|| {
        format!(
            "extraction parent escaped output root: {}",
            parent.display()
        )
    })?;
    let mut current = base.to_path_buf();

    for component in relative_parent.components() {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current).with_context(|| {
            format!(
                "failed to inspect extraction directory: {}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            bail!(
                "symlinks are not supported in extraction directories: {}",
                current.display()
            );
        }
    }

    Ok(())
}

fn render_vault_info(header: &VaultHeader) -> String {
    format!(
        "RustyArchive Vault\nHeader metadata:\nFormat version: {}\nCompression: {}\nKDF: {}\nKDF memory: {} KiB\nKDF iterations: {}\nKDF parallelism: {}\nEncryption: {}\nCiphertext size: {}\n\nNote: header authenticity and manifest presence are verified only during successful decryption.",
        header.format_version,
        compression_name(header.compression),
        kdf_name(header.kdf),
        header.kdf_params.m_cost_kib,
        header.kdf_params.t_cost,
        header.kdf_params.p_cost,
        encryption_name(header.encryption),
        human_size(header.ciphertext_length),
    )
}

fn compression_name(value: u8) -> &'static str {
    match value {
        1 => "zip",
        _ => "unknown",
    }
}

fn kdf_name(value: u8) -> &'static str {
    match value {
        1 => "Argon2id",
        _ => "unknown",
    }
}

fn encryption_name(value: u8) -> &'static str {
    match value {
        1 => "XChaCha20-Poly1305",
        _ => "unknown",
    }
}

fn human_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;

    if bytes >= MIB as u64 {
        format!("{:.1} MB", bytes as f64 / MIB)
    } else if bytes >= KIB as u64 {
        format!("{:.1} KiB", bytes as f64 / KIB)
    } else {
        format!("{bytes} bytes")
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::KdfParams;
    use crate::vault_format::{
        COMPRESSION_ZIP, ENCRYPTION_XCHACHA20_POLY1305, FORMAT_VERSION, KDF_ARGON2ID,
    };

    use super::{VaultHeader, human_size, render_vault_info};

    #[test]
    fn renders_info_output_from_header_metadata() {
        let header = VaultHeader {
            format_version: FORMAT_VERSION,
            compression: COMPRESSION_ZIP,
            kdf: KDF_ARGON2ID,
            kdf_params: KdfParams {
                m_cost_kib: 32_768,
                t_cost: 3,
                p_cost: 1,
            },
            encryption: ENCRYPTION_XCHACHA20_POLY1305,
            ciphertext_length: 14 * 1024 * 1024 + 205,
            salt: [0x11; 32],
            nonce: [0x22; 24],
        };

        let rendered = render_vault_info(&header);

        assert!(rendered.contains("Header metadata:"));
        assert!(rendered.contains("Compression: zip"));
        assert!(rendered.contains("KDF: Argon2id"));
        assert!(rendered.contains("Encryption: XChaCha20-Poly1305"));
        assert!(rendered.contains("Ciphertext size: 14.0 MB"));
    }

    #[test]
    fn formats_small_sizes_humanely() {
        assert_eq!(human_size(512), "512 bytes");
        assert_eq!(human_size(2 * 1024), "2.0 KiB");
    }
}
