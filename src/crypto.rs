use anyhow::{Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

pub const DEFAULT_M_COST_KIB: u32 = 32_768;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u8 = 1;
pub const SALT_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u8,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoParams {
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub params: CryptoParams,
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_payload(
    password: &str,
    plaintext: &[u8],
    aad: &[u8],
    kdf_params: KdfParams,
) -> Result<EncryptedPayload> {
    let params = generate_crypto_params(kdf_params);
    encrypt_payload_with_params(password, plaintext, aad, params)
}

pub fn encrypt_payload_with_params(
    password: &str,
    plaintext: &[u8],
    aad: &[u8],
    params: CryptoParams,
) -> Result<EncryptedPayload> {
    validate_crypto_params(&params)?;
    let mut key = derive_key(password, &params.salt, params.kdf)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&params.nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    key.zeroize();

    Ok(EncryptedPayload { params, ciphertext })
}

pub fn generate_crypto_params(kdf_params: KdfParams) -> CryptoParams {
    let mut salt = vec![0u8; SALT_LENGTH];
    let mut nonce = vec![0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    CryptoParams {
        kdf: kdf_params,
        salt,
        nonce,
    }
}

pub fn decrypt_payload(
    password: &str,
    params: &CryptoParams,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    validate_crypto_params(params)?;

    let mut key = derive_key(password, &params.salt, params.kdf)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&params.nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            anyhow!("decryption failed. The password may be wrong or the vault may be corrupted.")
        })?;
    key.zeroize();

    Ok(plaintext)
}

fn derive_key(password: &str, salt: &[u8], kdf_params: KdfParams) -> Result<[u8; 32]> {
    if salt.len() != SALT_LENGTH {
        bail!("invalid Argon2 salt length: {}", salt.len());
    }

    let params = Params::new(
        kdf_params.m_cost_kib,
        kdf_params.t_cost,
        kdf_params.p_cost.into(),
        Some(32),
    )
    .map_err(|error| anyhow!("invalid Argon2 parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|error| anyhow!("Argon2id key derivation failed: {error}"))?;

    Ok(key)
}

fn validate_crypto_params(params: &CryptoParams) -> Result<()> {
    if params.salt.len() != SALT_LENGTH {
        bail!("invalid Argon2 salt length: {}", params.salt.len());
    }

    if params.nonce.len() != NONCE_LENGTH {
        bail!(
            "invalid XChaCha20-Poly1305 nonce length: {}",
            params.nonce.len()
        );
    }

    Ok(())
}
