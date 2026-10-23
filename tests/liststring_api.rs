mod dex_fixture;
mod zip_fixture;

use dex_fixture::{make_dex041_container, make_strings_dex};
use rust_ASC::asc_client::apk_handler::ApkHandler;
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

#[test]
fn row_api_returns_strings_in_dex_and_table_order_with_duplicates() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("strings.apk");
    let first = make_strings_dex(&["https://alpha.example/v1", "alpha", "alpha"]);
    let second = make_strings_dex(&["beta", "https://alpha.example/v1"]);
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(
            &apk,
            &[("classes.dex", &first), ("classes2.dex", &second)],
            compression,
        );
        for threads in [1, 2] {
            let handler = ApkHandler::new(apk.to_str().unwrap(), false, threads);
            // The explicit type catches public API changes at compile time.
            let rows: Vec<String> = handler.list_strings(None).unwrap();
            assert_eq!(
                rows,
                [
                    "https://alpha.example/v1",
                    "alpha",
                    "alpha",
                    "beta",
                    "https://alpha.example/v1",
                ]
            );
        }
    }
}

#[test]
fn filter_is_a_case_insensitive_substring_over_the_whole_pool() {
    let values = [
        "https://alpha.example/v1",
        "ALPHA",
        "alpha",
        "Lalpha/Unrelated;",
        "no match here",
    ];
    let dir = tempdir().unwrap();
    let apk = dir.path().join("filter.apk");
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(
            &apk,
            &[("classes.dex", &make_strings_dex(&values))],
            compression,
        );
        for threads in [1, 2] {
            let handler = ApkHandler::new(apk.to_str().unwrap(), false, threads);
            let rows: Vec<String> = handler.list_strings(Some("alpha")).unwrap();
            assert_eq!(
                rows,
                [
                    "https://alpha.example/v1",
                    "ALPHA",
                    "alpha",
                    "Lalpha/Unrelated;",
                ]
            );
            // A prefix is not implied: the needle matches anywhere in the value.
            let rows: Vec<String> = handler.list_strings(Some("example")).unwrap();
            assert_eq!(rows, ["https://alpha.example/v1"]);
            assert!(handler.list_strings(Some("missing")).unwrap().is_empty());
        }
    }
}

#[test]
fn non_ascii_filters_fold_case_through_the_mutf8_path() {
    let values = ["ÄBC-Payload", "名字", "plain"];
    let dir = tempdir().unwrap();
    let apk = dir.path().join("utf8.apk");
    write_apk(
        &apk,
        &[("classes.dex", &make_strings_dex(&values))],
        CompressionMethod::Deflated,
    );
    let handler = ApkHandler::new(apk.to_str().unwrap(), false, 1);
    assert_eq!(handler.list_strings(None).unwrap(), values);
    assert_eq!(handler.list_strings(Some("äbc")).unwrap(), ["ÄBC-Payload"]);
    assert_eq!(handler.list_strings(Some("名字")).unwrap(), ["名字"]);
}

#[test]
fn values_with_embedded_newlines_stay_single_records() {
    // The CLI frames one value per line; the row API must not split a value
    // that itself contains a newline.
    let values = ["multi\nline", "tab\tvalue"];
    let dir = tempdir().unwrap();
    let apk = dir.path().join("records.apk");
    write_apk(
        &apk,
        &[("classes.dex", &make_strings_dex(&values))],
        CompressionMethod::Stored,
    );
    let handler = ApkHandler::new(apk.to_str().unwrap(), false, 1);
    assert_eq!(handler.list_strings(None).unwrap(), values);
}

#[test]
fn empty_pool_lists_nothing() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("empty.apk");
    write_apk(
        &apk,
        &[("classes.dex", &make_strings_dex(&[]))],
        CompressionMethod::Stored,
    );
    let handler = ApkHandler::new(apk.to_str().unwrap(), false, 1);
    assert!(handler.list_strings(None).unwrap().is_empty());
    assert!(handler.list_strings(Some("anything")).unwrap().is_empty());
}

#[test]
fn non_dex_payload_in_a_classes_entry_is_reported() {
    // A `classes*.dex` entry that is not a DEX is a broken archive, and the
    // listing says so instead of returning a silently short list.
    let dir = tempdir().unwrap();
    let apk = dir.path().join("broken.apk");
    write_apk(
        &apk,
        &[("classes.dex", b"not a dex file")],
        CompressionMethod::Stored,
    );
    let handler = ApkHandler::new(apk.to_str().unwrap(), false, 1);
    assert_eq!(
        handler.list_strings(None).unwrap_err(),
        "invalid DEX header"
    );
}

#[test]
fn dex_041_container_lists_every_logical_dex_pool_in_order() {
    // A 041 container carries several logical DEX files in one zip entry; the
    // walk has to visit each of them exactly once, in file order.
    let dir = tempdir().unwrap();
    let apk = dir.path().join("container.apk");
    write_apk(
        &apk,
        &[("classes.dex", &make_dex041_container())],
        CompressionMethod::Deflated,
    );
    let handler = ApkHandler::new(apk.to_str().unwrap(), false, 1);
    assert_eq!(
        handler.list_strings(None).unwrap(),
        [
            "Lalpha/First;",
            "Lshared/Duplicate;",
            "Lbeta/Second;",
            "Lshared/Duplicate;",
        ]
    );
}
