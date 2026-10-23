mod dex_fixture;
mod zip_fixture;

use std::path::Path;
use std::process::{Command, Output};

use dex_fixture::make_strings_dex;
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

fn run_cli(apk: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .arg("liststring")
        .args(args)
        .arg(apk)
        .output()
        .unwrap()
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout).unwrap()
}

const VALUES: [&str; 4] = [
    "https://alpha.example/v1",
    "mtop.demo.order.create",
    "https://beta.example/v2",
    "unrelated",
];

#[test]
fn prints_one_string_per_line_in_dex_order_across_compressions_and_threads() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("strings.apk");
    let first = make_strings_dex(&VALUES[..2]);
    let second = make_strings_dex(&VALUES[2..]);
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(
            &apk,
            &[("classes.dex", &first), ("classes2.dex", &second)],
            compression,
        );
        for args in [vec![], vec!["--thread", "1"], vec!["--thread", "4"]] {
            let stdout = success(run_cli(&apk, &args));
            assert_eq!(stdout, format!("{}\n", VALUES.join("\n")));
        }
    }
}

#[test]
fn filter_and_output_file_follow_listmethod_semantics() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("filter.apk");
    write_apk(
        &apk,
        &[("classes.dex", &make_strings_dex(&VALUES))],
        CompressionMethod::Deflated,
    );

    // Case insensitive substring, anywhere in the value.
    let stdout = success(run_cli(&apk, &["-f", "HTTPS"]));
    assert_eq!(
        stdout,
        "https://alpha.example/v1\nhttps://beta.example/v2\n"
    );
    assert_eq!(
        success(run_cli(&apk, &["--filter", "order"])),
        "mtop.demo.order.create\n"
    );
    assert_eq!(success(run_cli(&apk, &["-f", "missing"])), "");
    // An empty needle matches every value, as it does for `findrefs string`.
    assert_eq!(
        success(run_cli(&apk, &["--filter", ""])),
        format!("{}\n", VALUES.join("\n"))
    );

    // -o writes the list and leaves stdout empty.
    let output = dir.path().join("strings.txt");
    let output_arg = output.to_str().unwrap().to_owned();
    let stdout = success(run_cli(&apk, &["-o", &output_arg]));
    assert_eq!(stdout, "");
    assert_eq!(
        std::fs::read_to_string(&output).unwrap(),
        format!("{}\n", VALUES.join("\n"))
    );
}

