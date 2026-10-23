mod dex_fixture;
mod zip_fixture;

use std::collections::HashSet;
use std::path::Path;
use std::process::{Command, Output};

use dex_fixture::{get_u32, make_dex, make_static_field_dex};
use rust_ASC::asc_client::asc_handler::AscHandler;
use rust_ASC::asc_core::core::dex::dex_manager::DexManager;
use rust_ASC::asc_core::utils::dex_parser::{parse_encoded_array, EncodedValue};
use rust_ASC::asc_core::utils::tinydex::DEX;
use tempfile::tempdir;
use zip_fixture::{write_apk, CompressionMethod};

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn rebuilt_dex_keeps_signature_and_checksum_zero() {
    let mut manager = DexManager::from_bytes(make_dex(), false);
    let data = manager.extract_and_rebuild("Lexample/Test;");
    assert_eq!(&data[8..32], &[0; 24]);
}

#[test]
fn rebuild_keeps_static_values_and_field_operands_aligned() {
    let mut manager = DexManager::from_bytes(make_static_field_dex(), false);
    let data = manager.extract_and_rebuild("Lexample/Statics;");
    let dex = DEX::parse(&data, "rebuilt.dex");
    let mut clazz = dex.get_class_by_idx(0);
    let static_fields: Vec<_> = clazz
        .fields()
        .into_iter()
        .map(|field_idx| dex.get_field(*field_idx))
        .filter(|field| field.is_static)
        .collect();
    let class_def_off = dex.header.classes.0 as usize + clazz.index as usize * 32;
    let static_values_off = get_u32(&data, class_def_off + 28) as usize;
    let values = parse_encoded_array(
        &data,
        static_values_off,
        &mut HashSet::new(),
        &mut HashSet::new(),
        &mut HashSet::new(),
        &mut HashSet::new(),
    );

    assert_eq!(
        static_fields
            .iter()
            .map(|field| field.name())
            .collect::<Vec<_>>(),
        ["FIRST", "SECOND"]
    );
    assert_eq!(
        values
            .iter()
            .map(|value| match value {
                EncodedValue::Primitive(_, bytes) => {
                    i64::from_le_bytes({
                        let sign = bytes.last().is_some_and(|byte| byte & 0x80 != 0);
                        let mut full = [if sign { 0xff } else { 0 }; 8];
                        full[..bytes.len()].copy_from_slice(bytes);
                        full
                    })
                }
                _ => panic!("expected primitive static value"),
            })
            .collect::<Vec<_>>(),
        [11, 22]
    );

    let method_idx = clazz
        .methods()
        .into_iter()
        .find(|&&method_idx| dex.get_method(method_idx).name() == "getSecond")
        .unwrap();
    let bytecode = dex.get_method(*method_idx).bytecode();
    let field_idx = u16::from_le_bytes([bytecode[2], bytecode[3]]) as u32;
    assert_eq!(dex.get_field(field_idx).name(), "SECOND");
}

#[test]
fn decompile_keeps_repeated_fast_path_and_class_zero() {
    let data = make_dex();
    for _ in 0..2 {
        let source = AscHandler::new(false).getclass(&data, "Lexample/Test;");
        assert!(source.contains("class Test"), "{source}");
        assert!(source.contains("void first()"), "{source}");
        assert!(source.contains("void second()"), "{source}");
    }
}

#[test]
fn cli_on_stored_and_compressed_multidex_apk() {
    let first = make_dex();
    let second = make_dex();
    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");

    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(
            &apk,
            &[("classes.dex", &first), ("classes2.dex", &second)],
            compression,
        );
        let apk_path = apk.to_str().unwrap();
        let search = run_cli(&[
            "findrefs",
            "--thread",
            "2",
            apk_path,
            "string",
            "token",
        ]);
        assert!(search.status.success(), "{}", stderr(&search));
        assert_eq!(
            String::from_utf8(search.stdout).unwrap().lines().count(),
            4
        );

        let source = run_cli(&["getclass", "--thread", "2", apk_path, "example.Test"]);
        assert!(source.status.success(), "{}", stderr(&source));
        assert!(String::from_utf8(source.stdout)
            .unwrap()
            .contains("class Test"));
    }
}
