mod dex_fixture;
mod zip_fixture;

use std::process::{Command, Output};

use dex_fixture::make_dex;
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

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
fn export_writes_all_apk_classes_to_the_required_output_directory() {
    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");
    let output = directory.path().join("output");
    let dex = make_dex();
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Deflated);

    let result = run_cli(&[
        "export",
        "--debug",
        "--thread",
        "2",
        apk.to_str().unwrap(),
        output.to_str().unwrap(),
    ]);
    assert!(result.status.success(), "{}", stderr(&result));
    assert!(stderr(&result).contains("APK export:"));

    let source = std::fs::read_to_string(output.join("example/Test.java")).unwrap();
    assert!(source.contains("class Test"), "{source}");
    assert!(source.contains("void first()"), "{source}");
    assert!(source.contains("void second()"), "{source}");
}

#[test]
fn export_requires_an_output_directory() {
    let result = run_cli(&["export", "fixture.apk"]);
    assert_eq!(result.status.code(), Some(1));
    assert!(stderr(&result).contains("<output_directory>"));
}
