mod dex_fixture;
mod zip_fixture;

use std::path::Path;
use std::process::{Command, Output};

use dex_fixture::{
    get_u32, make_class_only_dex, make_dex, make_invoke_dex, make_static_field_dex, put_u32,
};
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

fn run_cli(apk: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .arg("listmethod")
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

#[test]
fn lists_definitions_not_external_references_in_deterministic_multidex_order() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    let first = make_dex();
    let second = make_invoke_dex();
    let third = make_static_field_dex();
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(
            &apk,
            &[
                ("classes.dex", &first),
                ("classes2.dex", &second),
                ("classes3.dex", &third),
                ("classes4.dex", &first),
            ],
            compression,
        );
        for threads in ["1", "3"] {
            assert_eq!(
                success(run_cli(&apk, &["--thread", threads])),
                "Lexample/Test;->first()V\nLexample/Test;->second()V\n\
                 Lexample/Test;->run()V\nLexample/Statics;->getSecond()I\n\
                 Lexample/Test;->first()V\nLexample/Test;->second()V\n"
            );
        }
    }
}

#[test]
fn class_and_name_filters_and_output_file_follow_listclass_semantics() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture with space.apk");
    write_apk(
        &apk,
        &[
            ("classes.dex", &make_dex()),
            ("classes2.dex", &make_static_field_dex()),
        ],
        CompressionMethod::Deflated,
    );
    let expected = "Lexample/Test;->second()V\n";
    for class in ["example.Test", "Lexample/Test;"] {
        assert_eq!(
            success(run_cli(&apk, &["--class", class, "--filter", "ECON"])),
            expected
        );
    }
    assert_eq!(success(run_cli(&apk, &["-f", "missing"])), "");
    assert_eq!(success(run_cli(&apk, &["--class", "example.Missing"])), "");
    let output = dir.path().join("methods.txt");
    assert_eq!(
        success(run_cli(
            &apk,
            &[
                "--class",
                "example.Test",
                "-f",
                "second",
                "-o",
                output.to_str().unwrap()
            ]
        )),
        ""
    );
    assert_eq!(std::fs::read_to_string(&output).unwrap(), expected);
    // An empty match overwrites rather than leaving stale output.
    assert_eq!(
        success(run_cli(
            &apk,
            &["-f", "missing", "-o", output.to_str().unwrap()]
        )),
        ""
    );
    assert_eq!(std::fs::read_to_string(output).unwrap(), "");
}

#[test]
fn native_and_abstract_methods_are_included_and_virtual_indices_restart() {
    let mut dex = make_dex();
    let classes = get_u32(&dex, 0x64) as usize;
    let offset = dex.len() as u32;
    // Direct method index 1, native; virtual method index 0, abstract.
    dex.extend_from_slice(&[0, 0, 1, 1, 1, 0x89, 0x02, 0, 0, 0x81, 0x08, 0]);
    put_u32(&mut dex, classes + 24, offset);
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Stored);
    assert_eq!(
        success(run_cli(&apk, &[])),
        "Lexample/Test;->second()V\nLexample/Test;->first()V\n"
    );
}

#[test]
fn full_prototypes_distinguish_overloads() {
    let mut dex = make_dex();
    let old_proto = get_u32(&dex, 0x4c) as usize;
    let proto = dex[old_proto..old_proto + 12].to_vec();
    let parameters = dex.len() as u32;
    dex.extend_from_slice(&[2, 0, 0, 0, 0, 0, 1, 0]);
    let prototypes = dex.len() as u32;
    dex.extend_from_slice(&proto);
    dex.extend_from_slice(&proto);
    put_u32(&mut dex, prototypes as usize + 20, parameters);
    put_u32(&mut dex, 0x48, 2);
    put_u32(&mut dex, 0x4c, prototypes);
    let methods = get_u32(&dex, 0x5c) as usize;
    dex[methods + 10..methods + 12].copy_from_slice(&1u16.to_le_bytes());
    put_u32(&mut dex, methods + 12, 3); // same name as the first method
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Stored);
    assert_eq!(
        success(run_cli(&apk, &[])),
        "Lexample/Test;->first()V\nLexample/Test;->first(Lexample/Test;Ljava/lang/Object;)V\n"
    );
}

#[test]
fn mutf8_method_names_are_decoded_and_filtered() {
    let mut dex = make_dex();
    let strings = get_u32(&dex, 0x3c) as usize;
    let offset = dex.len() as u32;
    let name = "méthod😀";
    dex.push(name.encode_utf16().count() as u8);
    dex.extend_from_slice(&cesu8::to_java_cesu8(name));
    dex.push(0);
    put_u32(&mut dex, strings + 12, offset);
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Deflated);
    assert_eq!(
        success(run_cli(&apk, &["-f", "MÉTHOD😀"])),
        "Lexample/Test;->méthod😀()V\n"
    );
}

#[test]
fn index_scan_checks_name_field_alignment_and_overlapping_zero_bytes() {
    let mut dex = make_dex();
    let methods = get_u32(&dex, 0x5c) as usize;
    // name_idx == 0 has overlapping zero-byte matches in class/proto fields.
    put_u32(&mut dex, methods + 4, 0);
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Stored);
    let all = success(run_cli(&apk, &[]));
    for query in ["EXAMPLE", "second", "missing", ""] {
        let expected = all
            .lines()
            .filter(|line| {
                line.split_once("->")
                    .unwrap()
                    .1
                    .split('(')
                    .next()
                    .unwrap()
                    .to_lowercase()
                    .contains(&query.to_lowercase())
            })
            .collect::<Vec<_>>();
        let actual = success(run_cli(&apk, &["--filter", query]));
        assert_eq!(actual.lines().collect::<Vec<_>>(), expected);
    }
}

#[test]
fn name_index_matches_do_not_turn_external_references_into_definitions() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    write_apk(
        &apk,
        &[("classes.dex", &make_invoke_dex())],
        CompressionMethod::Stored,
    );
    assert_eq!(success(run_cli(&apk, &["--filter", "callToMethod"])), "");
    assert_eq!(
        success(run_cli(&apk, &["--filter", "RUN"])),
        "Lexample/Test;->run()V\n"
    );
}

#[test]
fn row_api_remains_compatible_with_chunked_cli_output() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    write_apk(
        &apk,
        &[("classes.dex", &make_dex()), ("classes2.dex", &make_dex())],
        CompressionMethod::Deflated,
    );
    let handler =
        rust_ASC::asc_client::apk_handler::ApkHandler::new(apk.to_str().unwrap(), false, 2);
    let rows = handler
        .list_methods(Some("example.Test"), Some("FIRST"))
        .unwrap();
    assert_eq!(
        rows,
        vec!["Lexample/Test;->first()V", "Lexample/Test;->first()V"]
    );
    assert_eq!(
        rows.join("\n") + "\n",
        success(run_cli(&apk, &["--class", "example.Test", "-f", "FIRST"]))
    );
}

#[test]
fn sparse_and_dense_name_queries_match_filtering_the_full_listing() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("sample.apk");
    write_apk(
        &apk,
        &[(
            "classes.dex",
            include_bytes!("../radguard/tests/fixtures/sample.dex"),
        )],
        CompressionMethod::Deflated,
    );
    let all = success(run_cli(&apk, &[]));
    let names: std::collections::HashSet<_> = all
        .lines()
        .map(|line| line.split_once("->").unwrap().1.split('(').next().unwrap())
        .filter(|name| name.to_lowercase().contains('a'))
        .collect();
    assert!(names.len() > 8, "exercise the dense name-index scan");
    for query in ["a", "OnCrEaTe", "<init>", "not_a_method_xyz", ""] {
        let expected = all
            .lines()
            .filter(|line| {
                line.split_once("->")
                    .unwrap()
                    .1
                    .split('(')
                    .next()
                    .unwrap()
                    .to_lowercase()
                    .contains(&query.to_lowercase())
            })
            .collect::<Vec<_>>();
        let actual = success(run_cli(&apk, &["--filter", query]));
        assert_eq!(actual.lines().collect::<Vec<_>>(), expected);
    }
}

// A DEX 041 logical member with absolute physical offsets and one native method.
fn method_dex041(base: usize, class: &str) -> Vec<u8> {
    let mut dex = make_class_only_dex(&[class], base, b"041");
    let old_strings = get_u32(&dex, 0x3c) as usize - base;
    let class_string = get_u32(&dex, old_strings);
    let classes = get_u32(&dex, 0x64) as usize - base;
    let name = (base + dex.len()) as u32;
    dex.extend_from_slice(b"\x03run\0");
    let void = (base + dex.len()) as u32;
    dex.extend_from_slice(b"\x01V\0");
    while dex.len() % 4 != 0 {
        dex.push(0);
    }
    let strings = (base + dex.len()) as u32;
    for value in [class_string, name, void] {
        dex.extend_from_slice(&value.to_le_bytes());
    }
    let types = (base + dex.len()) as u32;
    for value in [0u32, 2] {
        dex.extend_from_slice(&value.to_le_bytes());
    }
    let protos = (base + dex.len()) as u32;
    for value in [2u32, 1, 0] {
        dex.extend_from_slice(&value.to_le_bytes());
    }
    let methods = (base + dex.len()) as u32;
    dex.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
    let data = (base + dex.len()) as u32;
    dex.extend_from_slice(&[0, 0, 1, 0, 0, 0x89, 0x02, 0]);
    put_u32(&mut dex, classes + 24, data);
    for (header, count, offset) in [
        (0x38, 3, strings),
        (0x40, 2, types),
        (0x48, 1, protos),
        (0x58, 1, methods),
    ] {
        put_u32(&mut dex, header, count);
        put_u32(&mut dex, header + 4, offset);
    }
    let size = dex.len() as u32;
    put_u32(&mut dex, 0x20, size);
    dex
}

#[test]
fn dex041_lists_methods_in_every_logical_member() {
    let mut dex = method_dex041(0, "Lalpha/First;");
    let second_offset = dex.len();
    dex.extend(method_dex041(second_offset, "Lbeta/Second;"));
    let size = dex.len() as u32;
    put_u32(&mut dex, 0x70, size);
    put_u32(&mut dex, second_offset + 0x70, size);
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(&apk, &[("classes.dex", &dex)], compression);
        assert_eq!(
            success(run_cli(&apk, &[])),
            "Lalpha/First;->run()V\nLbeta/Second;->run()V\n"
        );
        assert_eq!(
            success(run_cli(&apk, &["--class", "beta.Second"])),
            "Lbeta/Second;->run()V\n"
        );
    }
}

#[test]
fn no_definitions_is_an_empty_success() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    write_apk(
        &apk,
        &[(
            "classes.dex",
            &make_class_only_dex(&["Lempty/Class;"], 0, b"035"),
        )],
        CompressionMethod::Stored,
    );
    assert_eq!(success(run_cli(&apk, &[])), "");
}

#[test]
fn invalid_inputs_return_clean_errors() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    let dex = make_dex();
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Stored);
    for args in [&["--thread", "0"][..], &["--class", " "][..]] {
        let output = run_cli(&apk, args);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    let methods = get_u32(&dex, 0x5c) as usize;
    let classes = get_u32(&dex, 0x64) as usize;
    let class_data = get_u32(&dex, classes + 24) as usize;
    let protos = get_u32(&dex, 0x4c) as usize;
    let strings = get_u32(&dex, 0x3c) as usize;
    let mut cases = vec![vec![0; 10]];
    for offset in [
        0x3c,
        0x4c,
        0x5c,
        classes,
        classes + 24,
        methods + 4,
        protos + 4,
        protos + 8,
        strings,
    ] {
        let mut bad = dex.clone();
        put_u32(&mut bad, offset, u32::MAX);
        cases.push(bad);
    }
    let mut bad = dex.clone();
    bad[methods + 2..methods + 4].copy_from_slice(&u16::MAX.to_le_bytes());
    cases.push(bad);
    let mut bad = dex.clone();
    bad[class_data + 4..class_data + 9].copy_from_slice(&[0xff; 5]);
    cases.push(bad);
    let mut bad = dex;
    bad.truncate(class_data + 5);
    cases.push(bad);
    for bad in cases {
        write_apk(&apk, &[("classes.dex", &bad)], CompressionMethod::Stored);
        let output = run_cli(&apk, &[]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
    let output = run_cli(&dir.path().join("missing.apk"), &[]);
    assert_eq!(output.status.code(), Some(1));
}
