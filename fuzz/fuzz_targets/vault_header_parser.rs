#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyarchive::vault_format::{parse_header, parse_header_from_file, serialize_header};

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = parse_header(data) {
        let serialized = serialize_header(&header).expect("parsed header should serialize");
        let reparsed = parse_header(&serialized).expect("serialized header should parse");
        assert_eq!(header, reparsed);
    }

    let _ = parse_header_from_file(data);
});
