// Strings that a query resolves to must come from the string_ids table, not
// from where the payload happens to sit in the file. The two orders are
// independent in the DEX format, and R8 output in the field report orders them
// differently. These fixtures reproduce the reported false positives
// (`http://` resolving to `CallbackIdMap.class_ids`, `getDeviceId` resolving to
// `getDeviceProductInfo`) plus the outright miss caused by a reversed layout.

mod dex_fixture;
mod zip_fixture;

use dex_fixture::make_permuted_string_dex;
use rust_ASC::asc_core::findrefs::locator::method_locator::{MethodFind, MethodLocator};
use rust_ASC::asc_core::findrefs::locator::string_locator::StringLocator;
use rust_ASC::asc_core::findrefs::locator::type_locator::TypeLocator;
use rust_ASC::asc_core::utils::tinydex::DEX;
use std::collections::HashSet;
use std::process::{Command, Output};
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

const HTTP_STRINGS: [&[u8]; 7] = [
    b"CallbackIdMap.class_ids",
    b"Lexample/Test;",
    b"Ljava/lang/Object;",
    b"V",
    b"http://alpha.example/v1",
    b"onClick",
    b"onTouch",
];

const DEVICE_STRINGS: [&[u8]; 9] = [
    b"Landroid/view/Display;",
    b"Landroid/view/MotionEvent;",
    b"Lexample/Test;",
    b"Ljava/lang/Object;",
    b"V",
    b"getDeviceId",
    b"getDeviceProductInfo",
    b"run",
    b"zzz_unused",
];

// const-string v0, #index; return-void
fn const_string_body(index: u16) -> Vec<u8> {
    vec![
        0x1a,
        0x00,
        (index & 0xff) as u8,
        (index >> 8) as u8,
        0x0e,
        0x00,
    ]
}

fn return_only() -> Vec<u8> {
    vec![0x0e, 0x00]
}

// invoke-virtual {v0}, method@index
fn invoke_virtual(method_index: u16) -> Vec<u8> {
    vec![
        0x6e,
        0x10,
        (method_index & 0xff) as u8,
        (method_index >> 8) as u8,
        0x00,
        0x00,
    ]
}

/// The physical order is 0, 4, 1, 2, 3, 5, 6 and the code references index 4
/// and index 0, so only a physical-layout lookup can swap them.
fn http_dex() -> Vec<u8> {
    make_permuted_string_dex(
        &HTTP_STRINGS,
        &[0, 4, 1, 2, 3, 5, 6],
        &[1, 2, 3],
        (0, 1),
        &[(0, 0, 5), (0, 0, 6)],
        &[
            (1, 0, 0, const_string_body(4)),
            (1, 0, 0, const_string_body(0)),
        ],
    )
}

/// `getDeviceId` is index 5 but is emitted before `run` (index 7), so a lookup
/// that takes "the item after the match" resolves it to index 6 instead.
fn device_dex() -> Vec<u8> {
    make_permuted_string_dex(
        &DEVICE_STRINGS,
        &[0, 1, 2, 3, 4, 6, 5, 7, 8],
        &[0, 1, 2, 3, 4],
        (2, 3),
        &[(0, 0, 6), (1, 0, 5), (1, 0, 5), (2, 0, 7)],
        &[
            (1, 0, 0, return_only()),
            (1, 0, 0, return_only()),
            (1, 0, 0, return_only()),
            (
                1,
                0,
                3,
                [
                    invoke_virtual(0),
                    invoke_virtual(1),
                    invoke_virtual(2),
                    return_only(),
                ]
                .concat(),
            ),
        ],
    )
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn string_locator_resolves_indexes_for_permuted_payloads() {
    let data = http_dex();
    let dex = DEX::parse(&data, "permuted.dex");
    let mut locator = StringLocator::new(&dex);
    locator._build_map();

    assert_eq!(locator.locate("http://"), HashSet::from([4]));
    assert_eq!(locator.locate("CallbackIdMap"), HashSet::from([0]));
}

#[test]
fn reversed_payload_order_still_finds_matches() {
    let order: Vec<usize> = (0..HTTP_STRINGS.len()).rev().collect();
    let data = make_permuted_string_dex(
        &HTTP_STRINGS,
        &order,
        &[1, 2, 3],
        (0, 1),
        &[(0, 0, 5), (0, 0, 6)],
        &[
            (1, 0, 0, const_string_body(4)),
            (1, 0, 0, const_string_body(0)),
        ],
    );
    let dex = DEX::parse(&data, "reversed.dex");
    let mut locator = StringLocator::new(&dex);
    locator._build_map();

    assert_eq!(locator.locate("http://"), HashSet::from([4]));
}

#[test]
fn method_locator_keeps_get_device_id_on_its_own_string_index() {
    let data = device_dex();
    let dex = DEX::parse(&data, "device.dex");
    let mut strings = StringLocator::new(&dex);
    strings._build_map();
    let types = TypeLocator::new(&dex);
    let methods = MethodLocator::new(&dex);

    let query = MethodFind::new(None, Some("getDeviceId".to_owned()));
    assert_eq!(methods.locate(&query, &strings, &types), HashSet::from([1, 2]));
}

#[test]
fn findrefs_string_hits_the_real_url_not_the_physical_neighbour() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("url.apk");
    write_apk(
        &apk,
        &[("classes.dex", &http_dex())],
        CompressionMethod::Deflated,
    );

    let apk = apk.to_str().unwrap();
    // The literal exists in the pool and is reported by the index-driven listing.
    assert_eq!(
        stdout(run_cli(&["liststring", "-f", "http://", apk])),
        "http://alpha.example/v1\n"
    );

    let references = stdout(run_cli(&["findrefs", apk, "string", "http://"]));
    assert!(
        references.contains("onClick"),
        "the method using const-string #4 must be reported, got: {references:?}"
    );
    assert!(
        !references.contains("onTouch") && !references.contains("CallbackIdMap"),
        "the physically adjacent string must not be reported, got: {references:?}"
    );
}

#[test]
fn findrefs_method_reports_real_get_device_id_callers() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("device.apk");
    write_apk(
        &apk,
        &[("classes.dex", &device_dex())],
        CompressionMethod::Deflated,
    );

    let references = stdout(run_cli(&["findrefs", apk.to_str().unwrap(), "method", "getDeviceId"]));
    assert!(
        references.contains("MotionEvent;->getDeviceId"),
        "the two real getDeviceId call sites must be reported, got: {references:?}"
    );
    assert!(
        !references.contains("getDeviceProductInfo"),
        "Display.getDeviceProductInfo must not be reported, got: {references:?}"
    );
}
