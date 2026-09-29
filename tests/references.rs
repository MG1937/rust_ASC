mod dex_fixture;

use std::collections::HashMap;

use dex_fixture::{get_u32, make_dex, put_u32};
use rust_ASC::asc_client::asc_handler::AscHandler;
use rust_ASC::asc_core::findrefs::findrefs_manager::FindRefInput;
use rust_ASC::asc_core::findrefs::locator::insn_locator::{insn_verify, InsnLocator};
use rust_ASC::asc_core::findrefs::locator::string_locator::StringLocator;
use rust_ASC::asc_core::findrefs::scan::code_item_scan::CodeItemScanner;
use rust_ASC::asc_core::utils::tinydex::DEX;

fn search(data: &[u8]) -> Vec<Option<Vec<u32>>> {
    let dex = DEX::parse(data, "fixture.dex");
    let mut locator = InsnLocator::new(&dex);
    locator.parse();
    let mut query = HashMap::from([("string".to_owned(), vec![Some(vec![5])])]);
    let mut scanner = CodeItemScanner::new(&locator);
    scanner.scan(&mut query, false, &mut locator);
    query.remove("string").unwrap()
}

#[test]
fn shared_code_keeps_method_zero() {
    let results = search(&make_dex());
    assert_eq!(results.len(), 1);
    let mut methods = results[0].clone().unwrap();
    methods.sort_unstable();
    assert_eq!(methods, [0, 1]);
}

#[test]
fn repeated_scans_preserve_method_bounds() {
    let data = make_dex();
    let dex = DEX::parse(&data, "fixture.dex");
    let mut locator = InsnLocator::new(&dex);
    locator.parse();
    let original_bounds = locator.method_bounds.clone();

    for _ in 0..2 {
        let mut query = HashMap::from([("string".to_owned(), vec![Some(vec![5])])]);
        let mut scanner = CodeItemScanner::new(&locator);
        scanner.scan(&mut query, false, &mut locator);
        let mut methods = query["string"][0].clone().unwrap();
        methods.sort_unstable();
        assert_eq!(methods, [0, 1]);
        assert_eq!(locator.method_bounds, original_bounds);
    }
}

#[test]
fn fallback_without_class_data_map_entry() {
    let mut data = make_dex();
    let map_off = get_u32(&data, 52) as usize;
    let count = get_u32(&data, map_off) as usize;
    for off in (map_off + 4..map_off + 4 + count * 12).step_by(12) {
        if u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) == 0x2000 {
            data[off..off + 2].copy_from_slice(&0xffff_u16.to_le_bytes());
        }
    }
    let mut methods = search(&data)[0].clone().unwrap();
    methods.sort_unstable();
    assert_eq!(methods, [0, 1]);
}

#[test]
fn empty_or_absent_map_uses_class_definitions() {
    for empty in [true, false] {
        let mut data = make_dex();
        let map_off = get_u32(&data, 52) as usize;
        let off = if empty { map_off } else { 52 };
        put_u32(&mut data, off, 0);
        let mut methods = search(&data)[0].clone().unwrap();
        methods.sort_unstable();
        assert_eq!(methods, [0, 1], "empty={empty}");
    }
}

#[test]
fn class_without_method_bodies_has_no_references() {
    let mut data = make_dex();
    let class_off = get_u32(&data, 100) as usize;
    let class_data = get_u32(&data, class_off + 24) as usize;
    data[class_data..class_data + 10]
        .copy_from_slice(b"\0\0\x02\0\0\x09\0\x01\x09\0");
    assert!(search(&data).is_empty());
}

#[test]
fn search_does_not_require_a_decompiler() {
    let find = FindRefInput {
        string: Some("token".to_owned()),
        type_: None,
        method: None,
        field: None,
    };
    let lines = AscHandler::new(false).findrefs(
        "fixture.dex",
        &make_dex(),
        "string",
        &find,
        false,
    );
    assert_eq!(lines.len(), 2);
    assert!(lines.iter().any(|line| line.contains("->first")));
    assert!(lines.iter().any(|line| line.contains("->second")));
}

#[test]
fn instruction_verifier_accepts_valid_runs_and_rejects_invalid_ones() {
    assert!(insn_verify(b"\x0e\x00", 0, 2));
    assert!(insn_verify(b"\x0e\x00\x0e\x00", 0, 4));
    assert!(!insn_verify(b"\x0e\x00\x3e\x00", 0, 4));
    assert!(!insn_verify(b"\x1a\x00\x05", 0, 3));
}

#[test]
fn last_string_is_searchable() {
    let data = make_dex();
    let dex = DEX::parse(&data, "fixture.dex");
    let mut locator = StringLocator::new(&dex);
    locator._build_map();
    assert_eq!(locator.locate("token"), [5].into_iter().collect());
}

#[test]
fn empty_string_table() {
    let mut data = make_dex();
    put_u32(&mut data, 56, 0);
    put_u32(&mut data, 60, 0);
    let dex = DEX::parse(&data, "fixture.dex");
    let mut locator = StringLocator::new(&dex);
    locator._build_map();
    assert!(locator.locate("token").is_empty());
}

#[test]
fn malformed_string_offset_is_ignored_without_panicking() {
    let mut data = make_dex();
    let string_ids_off = get_u32(&data, 60) as usize;
    put_u32(&mut data, string_ids_off, u32::MAX);
    let dex = DEX::parse(&data, "fixture.dex");
    let mut locator = StringLocator::new(&dex);
    locator._build_map();
    assert!(locator.locate("token").is_empty());
}
