mod dex_fixture;
mod zip_fixture;

use dex_fixture::{get_u32, make_class_only_dex, make_dex041_container, put_u32};
use rust_ASC::asc_client::apk_handler::ApkHandler;
use std::process::Command;
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

#[test]
fn unique_sorted_packages_across_dex_with_cli_filter_and_output() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("packages.apk");
    let first = make_class_only_dex(
        &[
            "Lz/Last;",
            "Lcom/example/A;",
            "LDefault;",
            "Lcom/example/sub/Inner$Nested;",
        ],
        0,
        b"035",
    );
    let second = make_class_only_dex(&["Lcom/example/B;", "L名字/类型;"], 0, b"035");
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(
            &apk,
            &[("classes.dex", &first), ("classes2.dex", &second)],
            compression,
        );
        for threads in [1, 2] {
            let handler = ApkHandler::new(apk.to_str().unwrap(), false, threads);
            assert_eq!(
                handler.list_packages(None).unwrap(),
                ["com.example", "com.example.sub", "z", "名字"]
            );
            assert_eq!(
                handler.list_packages(Some("com/example")).unwrap(),
                ["com.example", "com.example.sub"]
            );
            assert!(handler.list_packages(Some("missing")).unwrap().is_empty());
            assert_eq!(handler.list_packages_at_level(None, Some(1)).unwrap(), ["com", "z", "名字"]);
            assert_eq!(handler.list_packages_at_level(None, Some(2)).unwrap(), ["com.example", "z", "名字"]);
            assert_eq!(handler.list_packages_at_level(None, Some(99)).unwrap(), handler.list_packages(None).unwrap());
            assert_eq!(handler.list_packages_at_level(Some("com.example.sub"), Some(2)).unwrap(), ["com.example"]);
            assert!(handler.list_packages_at_level(None, Some(0)).unwrap_err().contains("Package level"));
        }
        let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
            .args(["tree", "--flat", "--thread", "2"])
            .arg(&apk)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "com.example\ncom.example.sub\nz\n名字\n"
        );
        for (args, expected) in [
            (vec![], ".\n├── com\n│   └── example\n│       └── sub\n├── z\n└── 名字\n"),
            (vec!["-L", "2"], ".\n├── com\n│   └── example\n├── z\n└── 名字\n"),
            (vec!["--prefix", "com.example.sub"], "com.example.sub\n"),
            (vec!["--prefix", "com/example/", "-L", "1"], "com.example\n└── sub\n"),
            (vec!["--prefix", "com.exam"], ""),
            (vec!["--prefix", "missing"], ""),
            (vec!["--classes", "--prefix", "com.example", "-L", "1"], "com.example\n├── A.class\n├── B.class\n└── sub\n    └── Inner$Nested.class\n"),
            (vec!["--classes", "-L", "2"], ".\n├── com\n│   └── example\n│       ├── A.class\n│       └── B.class\n├── z\n│   └── Last.class\n└── 名字\n    └── 类型.class\n"),
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
                .arg("tree").args(args).arg(&apk).output().unwrap();
            assert!(output.status.success(), "{:?}", output);
            assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
        }
        for option in ["-L", "--level"] {
            let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
                .args(["tree", "--flat", option, "2"]).arg(&apk).output().unwrap();
            assert!(output.status.success(), "{:?}", output);
            assert_eq!(String::from_utf8(output.stdout).unwrap(), "com.example\nz\n名字\n");
        }
        let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
            .args(["tree", "-L", "0"]).arg(&apk).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr).unwrap().contains("Package level"));
        let file = dir.path().join("packages.txt");
        let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
            .args(["tree", "--flat", "--prefix", "com.example", "-o"])
            .arg(&file)
            .arg(&apk)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        assert!(output.stdout.is_empty());
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "com.example\ncom.example.sub\n"
        );
    }
}

#[test]
fn tree_depth_is_relative_to_root_and_excludes_similar_siblings() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("root.apk");
    let dex = make_class_only_dex(&["Lcom/example/edit/audio/service/A;", "Lcom/example/edit/export/B;", "Lcom/example/editapi/C;"], 0, b"035");
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Deflated);
    let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .args(["tree", "--classes", "--prefix", "com.example.edit", "-L", "1"]).arg(&apk).output().unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "com.example.edit\n├── audio\n└── export\n    └── B.class\n");
    let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .args(["tree", "--classes", "--flat"]).arg(&apk).output().unwrap();
    assert!(!output.status.success());
    for (level, expected) in [
        ("1", "com.example.edit\n├── audio\n└── export\n"),
        ("2", "com.example.edit\n├── audio\n│   └── service\n└── export\n"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
            .args(["tree", "--prefix", "com.example.edit", "-L", level]).arg(&apk).output().unwrap();
        assert!(output.status.success(), "{:?}", output);
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
}

#[test]
fn dex041_and_validation_errors() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("packages.apk");
    let dex = make_dex041_container();
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        write_apk(&apk, &[("classes.dex", &dex)], compression);
        assert_eq!(
            ApkHandler::new(apk.to_str().unwrap(), false, 2)
                .list_packages(None)
                .unwrap(),
            ["alpha", "beta", "shared"]
        );
    }
    assert!(
        ApkHandler::new(apk.to_str().unwrap(), false, 0)
            .list_packages(None)
            .unwrap_err()
            .contains("Worker count")
    );
    assert!(
        ApkHandler::new(apk.to_str().unwrap(), false, 1)
            .list_packages(Some(" "))
            .unwrap_err()
            .contains("Package prefix")
    );
    assert!(
        ApkHandler::new(dir.path().join("missing.apk").to_str().unwrap(), false, 1)
            .list_packages(None)
            .is_err()
    );
    let mut bad = dex_fixture::make_dex();
    let off = get_u32(&bad, 0x64) as usize;
    put_u32(&mut bad, off, u32::MAX);
    write_apk(&apk, &[("classes.dex", &bad)], CompressionMethod::Stored);
    assert!(
        ApkHandler::new(apk.to_str().unwrap(), false, 1)
            .list_packages(None)
            .is_err()
    );
}
