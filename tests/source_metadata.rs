mod dex_fixture;

use dex_fixture::{
    make_dex, make_field_invoke_chain_dex, make_instance_field_dex, make_invoke_dex,
    make_static_field_dex,
};
use rust_ASC::asc_client::asc_handler::AscHandler;
use rust_ASC::asc_core::findrefs::locator::field_locator::{FieldFind, FieldLocator};
use rust_ASC::asc_core::findrefs::locator::method_locator::{MethodFind, MethodLocator};
use rust_ASC::asc_core::findrefs::locator::string_locator::StringLocator;
use rust_ASC::asc_core::findrefs::locator::type_locator::TypeLocator;
use rust_ASC::asc_core::utils::decompiler::{MemberKind, MemberReference};
use rust_ASC::asc_core::utils::tinydex::DEX;

fn text<'a>(source: &'a str, reference: &MemberReference) -> &'a str {
    &source[reference.start..reference.end]
}

#[test]
fn real_this_field_method_chain_maps_both_members() {
    let (source, references) = AscHandler::new(false)
        .getclass_with_metadata(&make_field_invoke_chain_dex(), "Lexample/Test;");
    let field = references
        .iter()
        .find(|item| {
            item.kind == MemberKind::Field
                && item.class == "Lexample/Test;"
                && item.name == "a"
        })
        .unwrap();
    let method = references
        .iter()
        .find(|item| {
            item.kind == MemberKind::Method
                && item.class == "Lexample/Target;"
                && item.name == "callToMethod"
        })
        .unwrap();
    assert_eq!(text(&source, field), "a");
    assert_eq!(text(&source, method), "callToMethod");
}

#[test]
fn real_dex_invocation_metadata_has_target_class() {
    let (source, references) =
        AscHandler::new(false).getclass_with_metadata(&make_invoke_dex(), "Lexample/Test;");
    let invocation = references
        .iter()
        .find(|item| item.name == "callToMethod")
        .unwrap();
    assert_eq!(text(&source, invocation), "callToMethod");
    assert_eq!(invocation.kind, MemberKind::Method);
    assert_eq!(invocation.class, "Lexample/Target;");
    assert_eq!(invocation.descriptor, "()V");
    assert!(!invocation.declaration);
}

#[test]
fn real_dex_static_field_metadata_has_declaring_class() {
    let (source, references) = AscHandler::new(false)
        .getclass_with_metadata(&make_static_field_dex(), "Lexample/Statics;");
    let matches: Vec<_> = references
        .iter()
        .filter(|item| item.kind == MemberKind::Field && item.name == "SECOND")
        .collect();
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().all(|item| text(&source, item) == "SECOND"));
    assert!(matches.iter().all(|item| {
        item.class == "Lexample/Statics;" && item.descriptor == "I"
    }));
}

#[test]
fn real_dex_instance_field_metadata_has_declaring_class() {
    let (source, references) = AscHandler::new(false)
        .getclass_with_metadata(&make_instance_field_dex(), "Lexample/Test;");
    let matches: Vec<_> = references
        .iter()
        .filter(|item| item.kind == MemberKind::Field && item.name == "a")
        .collect();
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().all(|item| text(&source, item) == "a"));
    assert!(matches
        .iter()
        .all(|item| item.class == "Lexample/Test;"));
}

#[test]
fn exact_method_locator_does_not_use_substring_matching() {
    let data = make_dex();
    let dex = DEX::parse(&data, "fixture.dex");
    let mut strings = StringLocator::new(&dex);
    strings._build_map();
    let mut types = TypeLocator::new(&dex);
    types._build_map();
    let mut locator = MethodLocator::new(&dex);
    locator._build_map();

    assert!(locator
        .locate(
            &MethodFind::new_exact(
                Some(("Lexample/Test;".to_owned(), true)),
                Some("fir".to_owned()),
            ),
            &strings,
            &types,
        )
        .is_empty());
    assert_eq!(
        locator.locate(
            &MethodFind::new_exact(
                Some(("Lexample/Test;".to_owned(), true)),
                Some("first".to_owned()),
            ),
            &strings,
            &types,
        ),
        [0].into_iter().collect()
    );
}

#[test]
fn exact_field_locator_does_not_use_substring_matching() {
    let data = make_static_field_dex();
    let dex = DEX::parse(&data, "fixture.dex");
    let mut strings = StringLocator::new(&dex);
    strings._build_map();
    let mut types = TypeLocator::new(&dex);
    types._build_map();
    let mut locator = FieldLocator::new(&dex);
    locator._build_map();

    assert!(locator
        .locate(
            &FieldFind::new_exact(
                Some(("Lexample/Statics;".to_owned(), true)),
                Some("SEC".to_owned()),
            ),
            &strings,
            &types,
        )
        .is_empty());
    assert_eq!(
        locator.locate(
            &FieldFind::new_exact(
                Some(("Lexample/Statics;".to_owned(), true)),
                Some("SECOND".to_owned()),
            ),
            &strings,
            &types,
        ),
        [1].into_iter().collect()
    );
}
