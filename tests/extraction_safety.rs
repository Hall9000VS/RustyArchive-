use std::io::{Cursor, Write};

use rustyarchive::archive::extract_zip_payload;
use rustyarchive::manifest::{
    MANIFEST_ARCHIVE_PATH, Manifest, ManifestEntry, validate_manifest_path,
};

#[test]
fn rejects_zip_entry_with_parent_traversal() {
    let temp = tempfile::tempdir().expect("temp dir");
    let output = temp.path().join("out");
    let payload = zip_payload_with_entries(&[("../evil.txt", b"evil".as_slice())], manifest());

    let error = extract_zip_payload(&payload, &output).expect_err("unsafe entry should fail");

    assert!(error.to_string().contains("unsafe component"));
    assert!(!temp.path().join("evil.txt").exists());
}

#[test]
fn rejects_zip_entry_not_listed_in_manifest() {
    let temp = tempfile::tempdir().expect("temp dir");
    let output = temp.path().join("out");
    let payload = zip_payload_with_entries(
        &[
            ("safe.txt", b"safe".as_slice()),
            ("extra.txt", b"extra".as_slice()),
        ],
        manifest(),
    );

    let error = extract_zip_payload(&payload, &output).expect_err("extra entry should fail");

    assert!(error.to_string().contains("not listed in the manifest"));
}

#[test]
fn rejects_zip_symlink_entries() {
    let temp = tempfile::tempdir().expect("temp dir");
    let output = temp.path().join("out");
    let payload = zip_payload_with_symlink_entry("safe.txt", b"target");

    let error = extract_zip_payload(&payload, &output).expect_err("symlink entry should fail");

    assert!(
        error.to_string().contains("symlinks are not supported"),
        "{error}"
    );
}

#[test]
fn rejects_manifest_checksum_mismatch_after_extraction() {
    let temp = tempfile::tempdir().expect("temp dir");
    let output = temp.path().join("out");
    let payload = zip_payload_with_entries(&[("safe.txt", b"xxxx".as_slice())], manifest());

    let error = extract_zip_payload(&payload, &output).expect_err("checksum mismatch should fail");

    assert!(error.to_string().contains("checksum mismatch"));
}

#[test]
fn rejects_windows_reserved_manifest_paths() {
    let error = validate_manifest_path("CON.txt").expect_err("reserved name should fail");

    assert!(error.to_string().contains("Windows reserved name"));
}

#[test]
fn rejects_reserved_rustyarchive_metadata_paths() {
    let error = validate_manifest_path(".rustyarchive/manifest.json")
        .expect_err("metadata path should be reserved");

    assert!(error.to_string().contains("reserved metadata directory"));
}

fn manifest() -> Manifest {
    Manifest {
        files: vec![ManifestEntry {
            path: "safe.txt".to_string(),
            size: 4,
            sha256: "8b3369944dd2a3fab39e32d1aeb1f763946a458ae3e6368a46432adc8f3a0860".to_string(),
        }],
        ..Manifest::default()
    }
}

fn zip_payload_with_entries(entries: &[(&str, &[u8])], manifest: Manifest) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for (path, bytes) in entries {
        writer.start_file(*path, options).expect("start file");
        writer.write_all(bytes).expect("write file");
    }

    writer
        .start_file(MANIFEST_ARCHIVE_PATH, options)
        .expect("start manifest");
    writer
        .write_all(&serde_json::to_vec(&manifest).expect("manifest json"))
        .expect("write manifest");

    writer.finish().expect("finish zip").into_inner()
}

fn zip_payload_with_symlink_entry(path: &str, target: &[u8]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();

    writer
        .add_symlink(
            path,
            std::str::from_utf8(target).expect("test target is utf-8"),
            options,
        )
        .expect("add symlink");

    writer
        .start_file(
            MANIFEST_ARCHIVE_PATH,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .expect("start manifest");
    writer
        .write_all(&serde_json::to_vec(&manifest()).expect("manifest json"))
        .expect("write manifest");

    writer.finish().expect("finish zip").into_inner()
}
