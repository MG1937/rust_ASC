use rust_ASC::asc_core::findrefs::locator::method_locator::{MethodFind, MethodLocator};
use rust_ASC::asc_core::findrefs::locator::string_locator::StringLocator;
use rust_ASC::asc_core::findrefs::locator::type_locator::TypeLocator;
use rust_ASC::asc_core::utils::tinydex::DEX;
use std::collections::HashSet;

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

// Only the string/type/method tables are needed for locator queries. Descriptors
// are sorted for exact-class binary search; member names include prefix
// collisions, repeated names across owners, and non-ASCII strings.
fn fixture(reverse_methods: bool, reverse_string_data: bool) -> Vec<u8> {
    let strings = [
        "FIRST", "I", "Lalpha/A;", "Lalpha/B;", "Lbeta/C;", "SECOND", "SECONDARY",
        "Ωname", "名字",
    ];
    let string_off = 0x70;
    let type_off = string_off + strings.len() * 4;
    let methods_off = type_off + 4 * 4;
    let mut rows = vec![
        (1u16, 0u16, 0u32),
        (1, 0, 5),
        (2, 0, 5),
        (2, 0, 7),
        (3, 0, 6),
        (3, 0, 8),
    ];
    if reverse_methods {
        rows.reverse();
    }
    let mut buf = vec![0u8; methods_off + rows.len() * 8];
    buf[..8].copy_from_slice(b"dex\n035\0");
    for (i, (count, offset)) in [
        (strings.len(), string_off), (4, type_off), (0, 0), (0, 0),
        (rows.len(), methods_off), (0, 0),
    ].into_iter().enumerate() {
        put_u32(&mut buf, 0x38 + i * 8, count as u32);
        put_u32(&mut buf, 0x3c + i * 8, offset as u32);
    }
    for (i, string_idx) in [1u32, 2, 3, 4].into_iter().enumerate() {
        put_u32(&mut buf, type_off + i * 4, string_idx);
    }
    for (i, (owner, ty, name)) in rows.into_iter().enumerate() {
        let off = methods_off + i * 8;
        buf[off..off + 2].copy_from_slice(&owner.to_le_bytes());
        buf[off + 2..off + 4].copy_from_slice(&ty.to_le_bytes());
        put_u32(&mut buf, off + 4, name);
    }
    let mut order: Vec<_> = (0..strings.len()).collect();
    if reverse_string_data {
        order.reverse();
    }
    for i in order {
        let offset = buf.len();
        put_u32(&mut buf, string_off + i * 4, offset as u32);
        let value = strings[i];
        buf.push(value.encode_utf16().count() as u8);
        buf.extend_from_slice(value.as_bytes());
        buf.push(0);
    }
    let length = buf.len() as u32;
    put_u32(&mut buf, 0x20, length);
    put_u32(&mut buf, 0x24, 0x70);
    buf
}

#[test]
fn direct_method_queries_match_indexed_queries_for_all_match_modes() {
    for reverse_methods in [false, true] {
        for reverse_strings in [false, true] {
            let data = fixture(reverse_methods, reverse_strings);
            let dex = DEX::parse(&data, "methods.dex");
            let mut strings = StringLocator::new(&dex);
            strings._build_map();
            let mut types = TypeLocator::new(&dex);
            types._build_map();
            let direct = MethodLocator::new(&dex);
            let mut indexed = MethodLocator::new(&dex);
            indexed._build_map();

            for class in [None, Some(""), Some("Lalpha/A;"), Some("Lalpha/B;"),
                Some("Lalpha/"), Some("Lbeta/C;"), Some("Lmissing/Nope;")]
            {
                for class_precise in [false, true] {
                    for name in [None, Some(""), Some("FIRST"), Some("SEC"), Some("SECOND"),
                        Some("SECONDARY"), Some("Ωname"), Some("名字"), Some("absent")]
                    {
                        for method_precise in [false, true] {
                            let query = MethodFind {
                                class: class.map(|name| (name.to_owned(), class_precise)),
                                method: name.map(str::to_owned),
                                method_precise,
                            };
                            assert_eq!(
                                direct.locate(&query, &strings, &types),
                                indexed.locate(&query, &strings, &types),
                                "class={class:?}, class_precise={class_precise}, name={name:?}, \
                                 method_precise={method_precise}, reverse_methods={reverse_methods}, \
                                 reverse_strings={reverse_strings}",
                            );
                        }
                    }
                }
            }
            assert!(!direct.parsed, "one-shot queries must not build full maps");
        }
    }
}

#[test]
fn direct_method_queries_preserve_exact_names_and_repeated_owners() {
    let data = fixture(false, false);
    let dex = DEX::parse(&data, "methods.dex");
    let mut strings = StringLocator::new(&dex);
    strings._build_map();
    let mut types = TypeLocator::new(&dex);
    types._build_map();
    let locator = MethodLocator::new(&dex);
    for (query, expected) in [
        (MethodFind::new_exact(None, Some("SECOND".to_owned())), HashSet::from([1, 2])),
        (MethodFind::new_exact(None, Some("SEC".to_owned())), HashSet::new()),
        (MethodFind::new_exact(None, Some("名字".to_owned())), HashSet::from([5])),
        (MethodFind::new(Some(("Lalpha/".to_owned(), false)), None), HashSet::from([0, 1, 2, 3])),
        (MethodFind::new(Some(("Lbeta/C;".to_owned(), true)), Some("SEC".to_owned())), HashSet::from([4])),
    ] {
        assert_eq!(locator.locate(&query, &strings, &types), expected);
    }
}
