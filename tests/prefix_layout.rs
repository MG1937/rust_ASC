mod dex_fixture;
mod zip_fixture;

use dex_fixture::{get_u32, make_class_only_dex, put_u32};
use std::process::Command;
use tempfile::tempdir;
use zip_fixture::{write_apk, CompressionMethod};

// Relocate class descriptor data without changing its logical content. Large
// incompressible padding exercises both the streaming and full-decode choices.
fn dex_with_strings_at(percent: usize) -> Vec<u8> {
    let mut dex = make_class_only_dex(&["Lalpha/First;", "Lbeta/Second;"], 0, b"035");
    let strings = get_u32(&dex, 0x3c) as usize;
    let data_start = get_u32(&dex, strings) as usize;
    let payload = dex[data_start..].to_vec();
    let offset = 4 * 1024 * 1024 * percent / 100;
    let old_len = dex.len();
    dex.resize(4 * 1024 * 1024, 0);
    let mut state = 0x1234_5678_u32;
    for byte in &mut dex[old_len..] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = state as u8;
    }
    dex[offset..offset + payload.len()].copy_from_slice(&payload);
    for index in 0..2 {
        let old_offset = get_u32(&dex, strings + index * 4) as usize;
        put_u32(&mut dex, strings + index * 4, (offset + old_offset - data_start) as u32);
    }
    let len = dex.len() as u32;
    put_u32(&mut dex, 0x20, len);
    dex
}

#[test]
fn descriptor_layout_does_not_change_listing_results() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("layout.apk");
    for percent in [10, 55, 82, 98] {
        let dex = dex_with_strings_at(percent);
        for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
            write_apk(&apk, &[("classes.dex", &dex)], compression);
            let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
                .args(["listclass", "--thread", "1"])
                .arg(&apk)
                .output()
                .unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            assert_eq!(output.stdout, b"Lalpha/First;\nLbeta/Second;\n", "layout {percent}%");
        }
    }
}

#[test]
fn a_late_unused_string_does_not_change_class_selection() {
    let mut dex = dex_with_strings_at(10);
    let strings = get_u32(&dex, 0x3c) as usize;
    let old_offset = get_u32(&dex, strings) as usize;
    let end = old_offset + 1 + "Lalpha/First;".len() + 1;
    let payload = dex[old_offset..end].to_vec();
    let late_offset = dex.len() * 9 / 10;
    dex[late_offset..late_offset + payload.len()].copy_from_slice(&payload);
    put_u32(&mut dex, strings, late_offset as u32);
    // The first string is no longer used by a defined class. It can only be a
    // decoder-selection hint, not a required-prefix/correctness assumption.
    put_u32(&mut dex, 0x60, 1);
    let classes = get_u32(&dex, 0x64) as usize;
    put_u32(&mut dex, classes, 1);
    let dir = tempdir().unwrap();
    let apk = dir.path().join("unordered.apk");
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Deflated);
    let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .arg("listclass")
        .arg(&apk)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, b"Lbeta/Second;\n");
}
