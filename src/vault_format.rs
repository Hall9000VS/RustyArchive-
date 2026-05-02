use anyhow::{Result, anyhow, bail};

use crate::crypto::KdfParams;

pub const MAGIC: [u8; 4] = *b"RAV\0";
pub const FORMAT_VERSION: u8 = 1;
pub const FIXED_V1_HEADER_LENGTH: u32 = 85;
pub const COMPRESSION_ZIP: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;
pub const ENCRYPTION_XCHACHA20_POLY1305: u8 = 1;
pub const SALT_LENGTH: usize = 32;
pub const XCHACHA20POLY1305_NONCE_LENGTH: usize = 24;
pub const MAX_V0_1_CIPHERTEXT_LENGTH: u64 = 1_073_807_360;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub format_version: u8,
    pub compression: u8,
    pub kdf: u8,
    pub kdf_params: KdfParams,
    pub encryption: u8,
    pub ciphertext_length: u64,
    pub salt: [u8; SALT_LENGTH],
    pub nonce: [u8; XCHACHA20POLY1305_NONCE_LENGTH],
}

impl VaultHeader {
    pub fn aad_length(&self) -> usize {
        FIXED_V1_HEADER_LENGTH as usize
    }
}

pub fn serialize_header(header: &VaultHeader) -> Result<Vec<u8>> {
    validate_header_fields(header)?;

    let mut bytes = Vec::with_capacity(FIXED_V1_HEADER_LENGTH as usize);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(header.format_version);
    bytes.extend_from_slice(&FIXED_V1_HEADER_LENGTH.to_le_bytes());
    bytes.push(header.compression);
    bytes.push(header.kdf);
    bytes.extend_from_slice(&header.kdf_params.m_cost_kib.to_le_bytes());
    bytes.extend_from_slice(&header.kdf_params.t_cost.to_le_bytes());
    bytes.push(header.kdf_params.p_cost);
    bytes.push(header.encryption);
    bytes.extend_from_slice(&header.ciphertext_length.to_le_bytes());
    bytes.extend_from_slice(&header.salt);
    bytes.extend_from_slice(&header.nonce);

    Ok(bytes)
}

pub fn parse_header(input: &[u8]) -> Result<VaultHeader> {
    if input.len() < FIXED_V1_HEADER_LENGTH as usize {
        bail!("vault is too small to contain a v1 header")
    }

    let header_bytes = &input[..FIXED_V1_HEADER_LENGTH as usize];

    if header_bytes[0..4] != MAGIC {
        bail!("invalid vault magic")
    }

    let format_version = header_bytes[4];
    if format_version != FORMAT_VERSION {
        bail!("unsupported vault format version: {format_version}")
    }

    let header_length = read_u32(header_bytes, 5)?;
    if header_length != FIXED_V1_HEADER_LENGTH {
        bail!("invalid v1 header length: {header_length}")
    }

    let compression = header_bytes[9];
    let kdf = header_bytes[10];
    let kdf_params = KdfParams {
        m_cost_kib: read_u32(header_bytes, 11)?,
        t_cost: read_u32(header_bytes, 15)?,
        p_cost: header_bytes[19],
    };
    let encryption = header_bytes[20];
    let ciphertext_length = read_u64(header_bytes, 21)?;

    let mut salt = [0u8; SALT_LENGTH];
    salt.copy_from_slice(&header_bytes[29..61]);

    let mut nonce = [0u8; XCHACHA20POLY1305_NONCE_LENGTH];
    nonce.copy_from_slice(&header_bytes[61..85]);

    let header = VaultHeader {
        format_version,
        compression,
        kdf,
        kdf_params,
        encryption,
        ciphertext_length,
        salt,
        nonce,
    };

    validate_header_fields(&header)?;

    Ok(header)
}

pub fn parse_header_from_file(file_bytes: &[u8]) -> Result<VaultHeader> {
    let header = parse_header(file_bytes)?;
    let file_size = file_bytes.len() as u64;
    let header_length = FIXED_V1_HEADER_LENGTH as u64;

    if file_size < header_length {
        bail!("vault is too small to contain the declared header")
    }

    let expected_ciphertext_length = file_size - header_length;
    if header.ciphertext_length != expected_ciphertext_length {
        bail!(
            "ciphertext length mismatch: header={}, actual={expected_ciphertext_length}",
            header.ciphertext_length
        )
    }

    if header.ciphertext_length > MAX_V0_1_CIPHERTEXT_LENGTH {
        bail!("ciphertext length exceeds the v0.1 maximum")
    }

    Ok(header)
}

fn validate_header_fields(header: &VaultHeader) -> Result<()> {
    if header.format_version != FORMAT_VERSION {
        bail!(
            "unsupported vault format version: {}",
            header.format_version
        )
    }

    if header.compression != COMPRESSION_ZIP {
        bail!(
            "unsupported compression algorithm identifier: {}",
            header.compression
        )
    }

    if header.kdf != KDF_ARGON2ID {
        bail!("unsupported KDF algorithm identifier: {}", header.kdf)
    }

    if header.encryption != ENCRYPTION_XCHACHA20_POLY1305 {
        bail!(
            "unsupported encryption algorithm identifier: {}",
            header.encryption
        )
    }

    validate_kdf_params(header.kdf_params)?;

    Ok(())
}

fn validate_kdf_params(kdf_params: KdfParams) -> Result<()> {
    if !(19_456..=262_144).contains(&kdf_params.m_cost_kib) {
        bail!("unsupported Argon2 memory cost: {}", kdf_params.m_cost_kib)
    }

    if !(1..=10).contains(&kdf_params.t_cost) {
        bail!("unsupported Argon2 iteration cost: {}", kdf_params.t_cost)
    }

    if !(1..=8).contains(&kdf_params.p_cost) {
        bail!("unsupported Argon2 parallelism cost: {}", kdf_params.p_cost)
    }

    Ok(())
}

fn read_u32(bytes: &[u8], start: usize) -> Result<u32> {
    let slice = bytes
        .get(start..start + 4)
        .ok_or_else(|| anyhow!("unexpected end of header while reading u32 at offset {start}"))?;

    let mut array = [0u8; 4];
    array.copy_from_slice(slice);
    Ok(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], start: usize) -> Result<u64> {
    let slice = bytes
        .get(start..start + 8)
        .ok_or_else(|| anyhow!("unexpected end of header while reading u64 at offset {start}"))?;

    let mut array = [0u8; 8];
    array.copy_from_slice(slice);
    Ok(u64::from_le_bytes(array))
}
