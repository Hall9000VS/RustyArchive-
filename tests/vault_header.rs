use rustyarchive::crypto::KdfParams;
use rustyarchive::vault_format::{
    COMPRESSION_ZIP, ENCRYPTION_XCHACHA20_POLY1305, FIXED_V1_HEADER_LENGTH, FORMAT_VERSION,
    KDF_ARGON2ID, MAX_V0_1_CIPHERTEXT_LENGTH, VaultHeader, parse_header, parse_header_from_file,
    serialize_header,
};

fn sample_header(ciphertext_length: u64) -> VaultHeader {
    VaultHeader {
        format_version: FORMAT_VERSION,
        compression: COMPRESSION_ZIP,
        kdf: KDF_ARGON2ID,
        kdf_params: KdfParams {
            m_cost_kib: 32_768,
            t_cost: 3,
            p_cost: 1,
        },
        encryption: ENCRYPTION_XCHACHA20_POLY1305,
        ciphertext_length,
        salt: [0x11; 32],
        nonce: [0x22; 24],
    }
}

#[test]
fn serializes_and_parses_a_valid_v1_header() {
    let header = sample_header(16);

    let bytes = serialize_header(&header).expect("header should serialize");
    let parsed = parse_header(&bytes).expect("header should parse");

    assert_eq!(bytes.len(), FIXED_V1_HEADER_LENGTH as usize);
    assert_eq!(parsed, header);
}

#[test]
fn rejects_invalid_v1_header_length() {
    let header = sample_header(0);
    let mut bytes = serialize_header(&header).expect("header should serialize");
    bytes[5..9].copy_from_slice(&84u32.to_le_bytes());

    let error = parse_header(&bytes).expect_err("invalid header length should fail");

    assert!(error.to_string().contains("invalid v1 header length"));
}

#[test]
fn rejects_ciphertext_length_mismatch_before_use() {
    let header = sample_header(8);
    let mut file_bytes = serialize_header(&header).expect("header should serialize");
    file_bytes.extend_from_slice(&[0xAA; 4]);

    let error =
        parse_header_from_file(&file_bytes).expect_err("mismatched ciphertext length should fail");

    assert!(error.to_string().contains("ciphertext length mismatch"));
}

#[test]
fn rejects_oversized_ciphertext_length() {
    let header = sample_header(MAX_V0_1_CIPHERTEXT_LENGTH + 1);
    let mut file_bytes = serialize_header(&header).expect("header should serialize");
    file_bytes.resize(FIXED_V1_HEADER_LENGTH as usize + 1, 0xAA);

    let error =
        parse_header_from_file(&file_bytes).expect_err("oversized ciphertext length should fail");

    assert!(error.to_string().contains("ciphertext length mismatch"));
}
