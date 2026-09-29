mod dex_fixture;
mod zip_fixture;

use std::path::Path;
use std::process::{Command, Output};

use dex_fixture::{
    get_u32, make_class_only_dex, make_dex, make_dex041_container, make_static_field_dex, put_u32,
};
use tempfile::tempdir;
use zip_fixture::{write_apk, CompressionMethod};

fn run_cli(apk: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rust_ASC"));
    command.arg("listclass").arg(apk).args(args);
    command.output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn cli_filters_normalized_prefix_for_stored_and_deflated_dex() {
    let data = make_class_only_dex(
        &[
            "Lcom/xxx/First;",
            "Lcom/xxx/internal/Second;",
            "Lorg/example/Other;",
        ],
        0,
        b"035",
    );
    let expected = "Lcom/xxx/First;\nLcom/xxx/internal/Second;\n";
    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");

    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        for prefix in ["com.xxx", "com/xxx", "Lcom/xxx"] {
            write_apk(&apk, &[("classes.dex", &data)], compression);
            let output = run_cli(&apk, &["--prefix", prefix]);
            assert!(output.status.success(), "{}", stderr(&output));
            assert_eq!(stdout(&output), expected);
        }
    }
}

#[test]
fn cli_preserves_dex_order_for_stored_and_deflated_multidex() {
    let first = make_dex();
    let second = make_static_field_dex();
    let third = make_dex();
    let expected = "Lexample/Test;\nLexample/Statics;\nLexample/Test;\n";
    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");
    let output_path = directory.path().join("classes.txt");

    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(
            &apk,
            &[
                ("classes.dex", &first),
                ("classes2.dex", &second),
                ("classes3.dex", &third),
            ],
            compression,
        );
        let output = run_cli(
            &apk,
            &["--threads", "2", "-o", output_path.to_str().unwrap()],
        );
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read_to_string(&output_path).unwrap(), expected);
    }
}

#[test]
fn cli_is_self_contained() {
    let data = make_dex();
    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");
    write_apk(
        &apk,
        &[("classes.dex", &data)],
        CompressionMethod::Deflated,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .current_dir(directory.path())
        .arg("listclass")
        .arg(&apk)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "Lexample/Test;\n");
}

#[test]
fn deflate_path_lists_large_dex() {
    let mut data = make_dex();
    let mut state = 0_u64;
    for _ in 0..1024 * 1024 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        data.push((state >> 32) as u8);
    }
    let file_size = data.len() as u32;
    put_u32(&mut data, 0x20, file_size);

    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");
    write_apk(
        &apk,
        &[("classes.dex", &data)],
        CompressionMethod::Deflated,
    );
    let output = run_cli(&apk, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "Lexample/Test;\n");
}

#[test]
fn dex041_container_lists_every_logical_member() {
    let data = make_dex041_container();
    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");

    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(&apk, &[("classes.dex", &data)], compression);
        let output = run_cli(&apk, &["--threads", "1"]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(
            stdout(&output),
            "Lalpha/First;\nLshared/Duplicate;\n\
             Lbeta/Second;\nLshared/Duplicate;\n"
        );
    }
}

#[test]
fn bad_class_type_index_is_a_clean_error() {
    let mut data = make_dex();
    let class_defs_off = get_u32(&data, 0x64) as usize;
    put_u32(&mut data, class_defs_off, u32::MAX);
    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");
    write_apk(&apk, &[("classes.dex", &data)], CompressionMethod::Stored);

    let output = run_cli(&apk, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("Error: bad class_def->type_idx"));
}

#[test]
fn worker_count_must_be_positive() {
    let data = make_dex();
    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");
    write_apk(&apk, &[("classes.dex", &data)], CompressionMethod::Stored);

    let output = run_cli(&apk, &["--threads", "0"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("Worker count must be greater than zero"));
}

#[test]
fn empty_prefix_is_a_clean_error() {
    let data = make_dex();
    let directory = tempdir().unwrap();
    let apk = directory.path().join("fixture.apk");
    write_apk(&apk, &[("classes.dex", &data)], CompressionMethod::Stored);

    let output = run_cli(&apk, &["--prefix", " "]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("Class prefix cannot be empty"));
}
