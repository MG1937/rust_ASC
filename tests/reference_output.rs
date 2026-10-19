mod dex_fixture;

use dex_fixture::{make_dex, make_instance_field_dex, make_invoke_dex, make_multi_string_dex};
use rust_ASC::asc_client::asc_handler::{AscHandler, Reference};
use rust_ASC::asc_core::findrefs::findrefs_manager::FindRefInput;
use rust_ASC::asc_core::findrefs::locator::field_locator::FieldFind;
use rust_ASC::asc_core::findrefs::locator::method_locator::MethodFind;

fn text(data: &[u8], kind: &str, query: &FindRefInput, aggregate: bool) -> Vec<String> {
    let handler = AscHandler::new(false);
    let mut borrowed = handler.findrefs("fixture.dex", data, kind, query, aggregate);
    let mut owned = handler.findrefs_vec("fixture.dex", data.to_vec(), kind, query, aggregate);
    if !aggregate {
        borrowed.sort();
        owned.sort();
    }
    assert_eq!(borrowed, owned);
    borrowed
}

#[test]
fn aggregated_text_and_records_preserve_target_order_and_delimiters() {
    let handler = AscHandler::new(false);
    let data = make_multi_string_dex();
    let query = FindRefInput::new(Some("token".into()), None, None, None);
    let expected = ["fixture.dex | Lexample/Test;->run | matched=(token-z; token-a; token-b)"];
    assert_eq!(text(&data, "string", &query, true), expected);
    assert_eq!(
        handler.findrefs_records("fixture.dex", data, "string", &query),
        vec![Reference {
            dex_name: "fixture.dex".into(),
            class_name: "Lexample/Test;".into(),
            method_name: "run".into(),
            matched: vec!["token-z".into(), "token-a; token-b".into()],
        }]
    );
}

#[test]
fn non_aggregated_text_preserves_repeated_occurrences() {
    let query = FindRefInput::new(Some("token".into()), None, None, None);
    let expected = [
        "fixture.dex | Lexample/Test;->run | matched=(token-a; token-b)",
        "fixture.dex | Lexample/Test;->run | matched=(token-a; token-b)",
        "fixture.dex | Lexample/Test;->run | matched=(token-z)",
    ];
    assert_eq!(
        text(&make_multi_string_dex(), "string", &query, false),
        expected
    );
}

#[test]
fn shared_code_keeps_both_callers_in_text_and_records() {
    let handler = AscHandler::new(false);
    let query = FindRefInput::new(Some("token".into()), None, None, None);
    let expected = [
        "fixture.dex | Lexample/Test;->first | matched=(token)",
        "fixture.dex | Lexample/Test;->second | matched=(token)",
    ];
    for aggregate in [false, true] {
        assert_eq!(text(&make_dex(), "string", &query, aggregate), expected);
    }
    let records = handler.findrefs_records("fixture.dex", make_dex(), "string", &query);
    assert_eq!(
        records
            .iter()
            .map(|r| r.method_name.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert!(records.iter().all(|r| r.matched == ["token"]));
}

#[test]
fn type_method_and_field_targets_keep_exact_cli_and_structured_formats() {
    let handler = AscHandler::new(false);
    let mut type_dex = make_dex();
    let insn = type_dex
        .windows(6)
        .position(|b| b == b"\x1a\0\x05\0\x0e\0")
        .unwrap();
    type_dex[insn..insn + 4].copy_from_slice(b"\x1c\0\0\0");
    let cases = [
        (
            type_dex,
            "type",
            FindRefInput::new(None, Some("Lexample/Test;".into()), None, None),
            vec!["first", "second"],
            "Lexample/Test;",
        ),
        (
            make_invoke_dex(),
            "method",
            FindRefInput::new(
                None,
                None,
                Some(MethodFind::new(None, Some("callToMethod".into()))),
                None,
            ),
            vec!["run"],
            "Lexample/Target;->callToMethod",
        ),
        (
            make_instance_field_dex(),
            "field",
            FindRefInput::new(
                None,
                None,
                None,
                Some(FieldFind::new(None, Some("a".into()))),
            ),
            vec!["getA"],
            "Lexample/Test;->a",
        ),
    ];
    for (data, kind, query, callers, target) in cases {
        let expected: Vec<_> = callers
            .iter()
            .map(|caller| format!("fixture.dex | Lexample/Test;->{caller} | matched=({target})"))
            .collect();
        for aggregate in [false, true] {
            assert_eq!(text(&data, kind, &query, aggregate), expected, "{kind}");
        }
        let records = handler.findrefs_records("fixture.dex", data, kind, &query);
        let expected: Vec<_> = callers
            .into_iter()
            .map(|caller| Reference {
                dex_name: "fixture.dex".into(),
                class_name: "Lexample/Test;".into(),
                method_name: caller.into(),
                matched: vec![target.into()],
            })
            .collect();
        assert_eq!(records, expected, "{kind}");
    }
}

#[test]
fn absent_targets_return_empty_results_in_both_representations() {
    let handler = AscHandler::new(false);
    let query = FindRefInput::new(Some("missing-target".into()), None, None, None);
    for aggregate in [false, true] {
        assert!(text(&make_dex(), "string", &query, aggregate).is_empty());
    }
    assert!(
        handler
            .findrefs_records("fixture.dex", make_dex(), "string", &query)
            .is_empty()
    );
}
