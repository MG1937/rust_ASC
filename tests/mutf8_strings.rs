use rust_ASC::asc_core::core::dex::dex_manager::DexManager;
use rust_ASC::asc_core::utils::tinydex::{_decode_mutf8_fallback, DEX};

fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn uleb128(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while value > 0x7f {
        out.push(((value & 0x7f) | 0x80) as u8);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

fn encode_mutf8(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in text.encode_utf16() {
        if unit == 0 {
            out.extend_from_slice(b"\xc0\x80");
        } else if unit <= 0x7f {
            out.push(unit as u8);
        } else if unit <= 0x7ff {
            out.extend_from_slice(&[0xc0 | (unit >> 6) as u8, 0x80 | (unit & 0x3f) as u8]);
        } else {
            out.extend_from_slice(&[
                0xe0 | (unit >> 12) as u8,
                0x80 | ((unit >> 6) & 0x3f) as u8,
                0x80 | (unit & 0x3f) as u8,
            ]);
        }
    }
    out
}

fn make_class_dex(names: &[&str]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = names.iter().map(|name| encode_mutf8(name)).collect();
    let units: Vec<usize> = names
        .iter()
        .map(|name| name.encode_utf16().count())
        .collect();
    let mut buf = vec![0; 0x70];

    let string_ids_off = buf.len();
    buf.resize(buf.len() + 4 * names.len(), 0);
    let type_ids_off = buf.len();
    buf.resize(buf.len() + 4 * names.len(), 0);
    let class_defs_off = buf.len();
    buf.resize(buf.len() + 32 * names.len(), 0);
    let data_off = buf.len();

    for (index, (raw, utf16_size)) in encoded.iter().zip(units).enumerate() {
        let string_off = buf.len();
        put_u32(&mut buf, string_ids_off + index * 4, string_off as u32);
        put_u32(&mut buf, type_ids_off + index * 4, index as u32);
        let class_def_off = class_defs_off + index * 32;
        for (offset, value) in [index as u32, 1, u32::MAX, 0, u32::MAX, 0, 0, 0]
            .into_iter()
            .enumerate()
        {
            put_u32(&mut buf, class_def_off + offset * 4, value);
        }
        buf.extend(uleb128(utf16_size));
        buf.extend(raw);
        buf.push(0);
    }

    let file_size = buf.len();
    let data_size = file_size - data_off;
    buf[..8].copy_from_slice(b"dex\n035\0");
    put_u32(&mut buf, 0x20, file_size as u32);
    put_u32(&mut buf, 0x24, 0x70);
    put_u32(&mut buf, 0x28, 0x1234_5678);
    put_u32(&mut buf, 0x38, names.len() as u32);
    put_u32(&mut buf, 0x3c, string_ids_off as u32);
    put_u32(&mut buf, 0x40, names.len() as u32);
    put_u32(&mut buf, 0x44, type_ids_off as u32);
    put_u32(&mut buf, 0x60, names.len() as u32);
    put_u32(&mut buf, 0x64, class_defs_off as u32);
    put_u32(&mut buf, 0x68, data_size as u32);
    put_u32(&mut buf, 0x6c, data_off as u32);
    buf
}

#[test]
fn issue_fixture_decodes_and_finds_non_ascii_classes() {
    let names = ["Ljava/lang/Object;", "Ll/\u{06e1};", "Ll/\u{1a7b};"];
    let data = make_class_dex(&names);
    let dex = DEX::parse(&data, "bug.dex");

    assert_eq!(
        (0..3)
            .map(|index| dex.get_string(index).value)
            .collect::<Vec<_>>(),
        names
    );
    assert!(dex.get_class("Ll/\u{06e1};").is_some());
    assert!(dex.get_class("Ll/\u{1a7b};").is_some());
}

#[test]
fn mutf8_special_forms_decode() {
    assert_eq!(_decode_mutf8_fallback(b"a\xc0\x80b"), "a\0b");
    assert_eq!(
        _decode_mutf8_fallback(b"\xed\xa0\xbd\xed\xb8\x80"),
        "\u{1f600}"
    );
}

#[test]
fn malformed_mutf8_uses_replacement_character() {
    assert_eq!(_decode_mutf8_fallback(b"a\xffb"), "a\u{fffd}b");
    assert_eq!(
        _decode_mutf8_fallback(b"a\xc0\x80\xffb"),
        "a\0\u{fffd}b"
    );
}

#[test]
fn get_class_falls_back_for_utf16_sort_order() {
    let names = ["Ll/\u{10000};", "Ll/\u{e000};"];
    let data = make_class_dex(&names);
    let dex = DEX::parse(&data, "utf16-order.dex");

    for name in names {
        assert!(dex.get_class(name).is_some(), "{name}");
    }
}

#[test]
fn rebuilt_dex_writes_modified_utf8() {
    let name = "Lexample/\u{1f600};";
    let mut manager = DexManager::from_bytes(make_class_dex(&[name]), false);
    let data = manager.extract_and_rebuild(name);

    assert!(data.windows(6).any(|raw| raw == b"\xed\xa0\xbd\xed\xb8\x80"));
    assert!(!data.windows(4).any(|raw| raw == b"\xf0\x9f\x98\x80"));
    let dex = DEX::parse(&data, "rebuilt.dex");
    assert!((0..dex.header.strings.1 as usize).any(|index| dex.get_string(index).value == name));
}

#[test]
#[should_panic(expected = "unterminated string_data_item")]
fn unterminated_string_is_rejected() {
    let mut data = make_class_dex(&["Lexample/Test;"]);
    *data.last_mut().unwrap() = 1;
    let dex = DEX::parse(&data, "unterminated.dex");

    dex.get_string(0);
}
