mod dex_fixture;
mod zip_fixture;

use std::collections::HashSet;
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

#[test]
fn asc_handler_getclass_recovers_float_double_cmp_and_unsigned_shift() {
    let dex_bytes = std::fs::read("radguard/tests/fixtures/classes5.dex")
        .expect("read classes5.dex fixture");
    let handler = AscHandler::new(false);
    let (source, refs) =
        handler.getclass_with_metadata(&dex_bytes, "Lcom/maoyan/android/common/view/ratingbar/b;");
    assert!(
        source.contains("super.f = -1.0f;"),
        "expected float literal -1.0f in:\n{source}"
    );
    assert!(
        source.contains("super.g = 0.1f;"),
        "expected float literal 0.1f in:\n{source}"
    );
    assert!(
        source.contains("if (((double) v2_4) <= vtmp8)")
            && source.contains("if (((double) v2_4) != vtmp8)"),
        "expected multi-use cmpl/cmpg condition recovery in:\n{source}"
    );
    assert!(
        !source.contains(" cmp "),
        "unexpected raw cmp operator in:\n{source}"
    );
    assert!(
        !refs.is_empty(),
        "expected member references from getclass_with_metadata"
    );

    let scene_source = handler.getclass(&dex_bytes, "Lcom/meituan/android/addresscenter/scene/a;");
    assert!(
        scene_source.contains(">>> 59"),
        "expected unsigned right shift >>> in:\n{scene_source}"
    );
}

#[test]
fn cli_supports_version_batch_getclass_json_findrefs_type_and_error_propagation() {
    let ver = run_cli(&["--version"]);
    assert!(ver.status.success(), "{}", stderr(&ver));
    assert!(String::from_utf8_lossy(&ver.stdout).starts_with("rust_ASC "));

    let missing_apk = run_cli(&["findrefs", "/nonexistent/no_such.apk", "string", "token"]);
    assert!(!missing_apk.status.success());
    assert!(stderr(&missing_apk).contains("cannot open APK"));

    let missing_getclass = run_cli(&["getclass", "/nonexistent/no_such.apk", "example.Test"]);
    assert!(!missing_getclass.status.success());
    assert!(stderr(&missing_getclass).contains("cannot open APK"));

    let directory = tempdir().unwrap();
    let corrupt_apk = directory.path().join("corrupt.apk");
    std::fs::write(&corrupt_apk, b"not a zip archive").unwrap();
    let corrupt_res = run_cli(&[
        "findrefs",
        corrupt_apk.to_str().unwrap(),
        "string",
        "token",
    ]);
    assert!(!corrupt_res.status.success());
    assert!(stderr(&corrupt_res).contains("invalid ZIP archive"));

    let apk = directory.path().join("fixture.apk");
    let dex = std::fs::read("radguard/tests/fixtures/classes5.dex").unwrap();
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Stored);
    let apk_path = apk.to_str().unwrap();

    // Dotted type name in findrefs type
    let type_refs = run_cli(&[
        "findrefs",
        "--thread",
        "2",
        apk_path,
        "type",
        "com.maoyan.android.common.view.ratingbar.c",
    ]);
    assert!(type_refs.status.success(), "{}", stderr(&type_refs));
    let type_stdout = String::from_utf8(type_refs.stdout).unwrap();
    assert!(
        type_stdout.contains("Lcom/maoyan/android/common/view/ratingbar/c;"),
        "expected dotted findrefs type to match:\n{type_stdout}"
    );

    // JSON output on getclass exposes member_references
    let json_res = run_cli(&[
        "getclass",
        "--json",
        apk_path,
        "com.maoyan.android.common.view.ratingbar.b",
    ]);
    assert!(json_res.status.success(), "{}", stderr(&json_res));
    let parsed: serde_json::Value = serde_json::from_slice(&json_res.stdout).unwrap();
    assert_eq!(parsed["class"], "Lcom/maoyan/android/common/view/ratingbar/b;");
    assert_eq!(parsed["status"], "ok");
    assert!(parsed["member_references"].as_array().unwrap().len() > 5);

    // Batch getclass via --classes-file
    let classes_file = directory.path().join("classes.txt");
    std::fs::write(
        &classes_file,
        "com.maoyan.android.common.view.ratingbar.b\nLcom/meituan/ai/speech/fusetts/BuildConfig;\n",
    )
    .unwrap();
    let batch_res = run_cli(&[
        "getclass",
        "--classes-file",
        classes_file.to_str().unwrap(),
        apk_path,
    ]);
    assert!(batch_res.status.success(), "{}", stderr(&batch_res));
    let batch_stdout = String::from_utf8(batch_res.stdout).unwrap();
    assert!(batch_stdout.contains("// === Class: Lcom/maoyan/android/common/view/ratingbar/b;"));
    assert!(batch_stdout.contains("// === Class: Lcom/meituan/ai/speech/fusetts/BuildConfig;"));

    // Filtered export via --prefix
    let export_dir = directory.path().join("exported");
    let export_res = run_cli(&[
        "export",
        "--prefix",
        "com.maoyan.android.common.view.ratingbar",
        apk_path,
        export_dir.to_str().unwrap(),
    ]);
    assert!(export_res.status.success(), "{}", stderr(&export_res));
    assert!(export_dir
        .join("com/maoyan/android/common/view/ratingbar/b.java")
        .exists());
    assert!(!export_dir
        .join("com/meituan/ai/speech/fusetts/BuildConfig.java")
        .exists());
}
