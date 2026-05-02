use std::fs;

use rustyarchive::archive::{pack_with_password, unpack_with_password};
use rustyarchive::cli::{PackArgs, UnpackArgs};
use rustyarchive::vault_format::{FIXED_V1_HEADER_LENGTH, parse_header_from_file};

#[test]
fn packs_and_unpacks_a_folder_roundtrip() {
    let temp = tempfile::tempdir().expect("temp dir");
    let input = temp.path().join("input");
    let nested = input.join("docs");
    fs::create_dir_all(&nested).expect("nested input dir");
    fs::write(input.join("hello.txt"), "hello vault\n").expect("write root file");
    fs::write(nested.join("readme.txt"), "nested file\n").expect("write nested file");

    let vault = temp.path().join("backup.rav");
    pack_with_password(
        PackArgs {
            input: input.clone(),
            output: vault.clone(),
            overwrite: false,
            no_progress: true,
        },
        "correct horse battery staple",
    )
    .expect("pack should succeed");

    let restored = temp.path().join("restored");
    unpack_with_password(
        UnpackArgs {
            input: vault,
            output: restored.clone(),
            overwrite: false,
            no_progress: true,
        },
        "correct horse battery staple",
    )
    .expect("unpack should succeed");

    assert_eq!(
        fs::read_to_string(restored.join("hello.txt")).expect("restored root file"),
        "hello vault\n"
    );
    assert_eq!(
        fs::read_to_string(restored.join("docs").join("readme.txt")).expect("restored nested file"),
        "nested file\n"
    );
}

#[test]
fn vault_bytes_are_non_deterministic_for_same_input() {
    let temp = tempfile::tempdir().expect("temp dir");
    let input = temp.path().join("input");
    fs::create_dir_all(&input).expect("input dir");
    fs::write(input.join("same.txt"), "same bytes").expect("input file");

    let first_vault = temp.path().join("first.rav");
    let second_vault = temp.path().join("second.rav");

    for output in [&first_vault, &second_vault] {
        pack_with_password(
            PackArgs {
                input: input.clone(),
                output: output.to_path_buf(),
                overwrite: false,
                no_progress: true,
            },
            "password",
        )
        .expect("pack should succeed");
    }

    assert_ne!(
        fs::read(first_vault).expect("first vault"),
        fs::read(second_vault).expect("second vault")
    );
}

#[test]
fn wrong_password_fails_before_extraction() {
    let temp = tempfile::tempdir().expect("temp dir");
    let input = temp.path().join("input");
    fs::create_dir_all(&input).expect("input dir");
    fs::write(input.join("secret.txt"), "secret").expect("input file");

    let vault = temp.path().join("backup.rav");
    pack_with_password(
        PackArgs {
            input,
            output: vault.clone(),
            overwrite: false,
            no_progress: true,
        },
        "right password",
    )
    .expect("pack should succeed");

    let restored = temp.path().join("restored");
    let error = unpack_with_password(
        UnpackArgs {
            input: vault,
            output: restored.clone(),
            overwrite: false,
            no_progress: true,
        },
        "wrong password",
    )
    .expect_err("wrong password should fail");

    assert!(error.to_string().contains("decryption failed"));
    assert!(!restored.exists());
}

#[test]
fn tampering_with_authenticated_header_is_detected() {
    let temp = tempfile::tempdir().expect("temp dir");
    let input = temp.path().join("input");
    fs::create_dir_all(&input).expect("input dir");
    fs::write(input.join("file.txt"), "content").expect("input file");

    let vault = temp.path().join("backup.rav");
    pack_with_password(
        PackArgs {
            input,
            output: vault.clone(),
            overwrite: false,
            no_progress: true,
        },
        "password",
    )
    .expect("pack should succeed");

    let mut bytes = fs::read(&vault).expect("vault bytes");
    parse_header_from_file(&bytes).expect("header before tamper");
    bytes[FIXED_V1_HEADER_LENGTH as usize - 1] ^= 0x01;
    fs::write(&vault, bytes).expect("tampered vault");

    let error = unpack_with_password(
        UnpackArgs {
            input: vault,
            output: temp.path().join("restored"),
            overwrite: false,
            no_progress: true,
        },
        "password",
    )
    .expect_err("tampered header should fail");

    assert!(error.to_string().contains("decryption failed"));
}
