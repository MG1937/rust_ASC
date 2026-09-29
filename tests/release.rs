mod dex_fixture;
mod zip_fixture;

use std::path::Path;
use std::process::{Command, Output};

use dex_fixture::make_dex;
use regex::Regex;
use tempfile::tempdir;
use zip_fixture::{write_apk, CompressionMethod};

fn valid_release_version(version: &str) -> bool {
    Regex::new(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:alpha|beta|rc)\.[1-9]\d*)?$")
        .unwrap()
        .is_match(version)
}

fn run(binary: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

fn assert_output(binary: &Path, cwd: &Path, args: &[&str], expected: &str) {
    let output = run(binary, cwd, args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(expected),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn invalid_version_is_rejected() {
    for version in ["0.1.0", "../v0.1.0", "v01.0.0", "v0.1.0-rc.0"] {
        assert!(!valid_release_version(version), "{version}");
    }
    for version in ["v0.1.0", "v0.1.0-alpha.1", "v0.1.0-beta.2", "v0.1.0-rc.1"] {
        assert!(valid_release_version(version), "{version}");
    }
}

#[test]
fn binary_runs_outside_checkout() {
    let directory = tempdir().unwrap();
    let source = Path::new(env!("CARGO_BIN_EXE_rust_ASC"));
    let binary = directory.path().join(
        source
            .file_name()
            .expect("compiled binary must have a file name"),
    );
    std::fs::copy(source, &binary).unwrap();
    let apk = directory.path().join("fixture.apk");
    let dex = make_dex();
    write_apk(
        &apk,
        &[("classes.dex", &dex)],
        CompressionMethod::Deflated,
    );
    let apk_path = apk.to_str().unwrap();

    assert_output(
        &binary,
        directory.path(),
        &["listclass", apk_path, "--prefix", "example"],
        "Lexample/Test;",
    );
    assert_output(
        &binary,
        directory.path(),
        &["findrefs", apk_path, "string", "token"],
        "token",
    );
    assert_output(
        &binary,
        directory.path(),
        &["getclass", apk_path, "example.Test"],
        "class Test",
    );
}
