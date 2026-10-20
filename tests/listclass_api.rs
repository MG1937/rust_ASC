mod dex_fixture;
mod zip_fixture;

use dex_fixture::{make_class_only_dex, make_dex041_container};
use rust_ASC::asc_client::apk_handler::ApkHandler;
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

#[test]
fn row_api_returns_strings_in_dex_order_and_preserves_duplicates() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("classes.apk");
    let first = make_class_only_dex(&["Lalpha/First;", "Lbeta/Other;"], 0, b"035");
    let second = make_class_only_dex(&["Lalpha/Second;", "Lalpha/First;"], 0, b"035");
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(
            &apk,
            &[("classes.dex", &first), ("classes2.dex", &second)],
            compression,
        );
        for threads in [1, 2] {
            let handler = ApkHandler::new(apk.to_str().unwrap(), false, threads);
            // The explicit type catches public API changes at compile time.
            let rows: Vec<String> = handler.list_classes(None).unwrap();
            assert_eq!(
                rows,
                [
                    "Lalpha/First;",
                    "Lbeta/Other;",
                    "Lalpha/Second;",
                    "Lalpha/First;",
                ]
            );
            for prefix in ["alpha.", "alpha/", "Lalpha/"] {
                let rows: Vec<String> = handler.list_classes(Some(prefix)).unwrap();
                assert_eq!(rows, ["Lalpha/First;", "Lalpha/Second;", "Lalpha/First;"]);
            }
            assert!(handler.list_classes(Some("missing")).unwrap().is_empty());
        }
    }
}

#[test]
fn row_api_does_not_reparse_names_as_newline_delimited_output() {
    // The original row API does not validate descriptor syntax. Preserve each
    // string as a record, even if it cannot be safely framed as a CLI line.
    let descriptors = [
        "Lalpha/With\nNewline;",
        "Lalpha/With\rReturn;",
        "Lalpha/名字;",
    ];
    let dex = make_class_only_dex(&descriptors, 0, b"035");
    let dir = tempdir().unwrap();
    let apk = dir.path().join("records.apk");
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(&apk, &[("classes.dex", &dex)], compression);
        let handler = ApkHandler::new(apk.to_str().unwrap(), false, 1);
        let rows: Vec<String> = handler.list_classes(None).unwrap();
        assert_eq!(rows, descriptors);
    }
}

#[test]
fn row_api_lists_every_dex041_member() {
    let dex = make_dex041_container();
    let dir = tempdir().unwrap();
    let apk = dir.path().join("container.apk");
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(&apk, &[("classes.dex", &dex)], compression);
        let handler = ApkHandler::new(apk.to_str().unwrap(), false, 2);
        let rows: Vec<String> = handler.list_classes(None).unwrap();
        assert_eq!(
            rows,
            [
                "Lalpha/First;",
                "Lshared/Duplicate;",
                "Lbeta/Second;",
                "Lshared/Duplicate;",
            ]
        );
        assert_eq!(
            handler.list_classes(Some("beta")).unwrap(),
            ["Lbeta/Second;"]
        );
    }
}

#[test]
fn row_api_preserves_validation_errors() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("classes.apk");
    let dex = make_class_only_dex(&["Lalpha/First;"], 0, b"035");
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Stored);
    assert_eq!(
        ApkHandler::new(apk.to_str().unwrap(), false, 0).list_classes(Some(" ")),
        Err("Worker count must be greater than zero".to_owned()),
    );
    assert_eq!(
        ApkHandler::new(apk.to_str().unwrap(), false, 1).list_classes(Some(" ")),
        Err("Class prefix cannot be empty".to_owned()),
    );
    let missing = dir.path().join("missing.apk");
    assert!(
        ApkHandler::new(missing.to_str().unwrap(), false, 1)
            .list_classes(None)
            .is_err()
    );
}
