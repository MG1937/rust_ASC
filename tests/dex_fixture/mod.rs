use sha1::{Digest, Sha1};

pub fn uleb(mut value: usize) -> Vec<u8> {
    let mut result = Vec::new();
    while value > 127 {
        result.push(((value & 127) | 128) as u8);
        value >>= 7;
    }
    result.push(value as u8);
    result
}

fn put_u16(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn align(buf: &mut Vec<u8>, value: usize) {
    let padding = (value - buf.len() % value) % value;
    buf.resize(buf.len() + padding, 0);
}

fn section(
    buf: &mut Vec<u8>,
    sections: &mut Vec<(u16, u32, u32)>,
    kind: u16,
    size: usize,
    data: &[u8],
    alignment: usize,
) -> usize {
    align(buf, alignment);
    let off = buf.len();
    sections.push((kind, size as u32, off as u32));
    buf.extend_from_slice(data);
    off
}

fn append_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn append_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn string_data(values: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::new();
    for value in values {
        data.extend(uleb(value.len()));
        data.extend_from_slice(value);
        data.push(0);
    }
    data
}

fn fill_string_ids(buf: &mut [u8], string_ids: usize, values: &[&[u8]], mut off: usize) {
    for (index, value) in values.iter().enumerate() {
        put_u32(buf, string_ids + index * 4, off as u32);
        off += uleb(value.len()).len() + value.len() + 1;
    }
}

fn code_item(
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    insns_size: u32,
    insns: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(16 + insns.len());
    append_u16(&mut data, registers_size);
    append_u16(&mut data, ins_size);
    append_u16(&mut data, outs_size);
    append_u16(&mut data, 0);
    append_u32(&mut data, 0);
    append_u32(&mut data, insns_size);
    data.extend_from_slice(insns);
    data
}

fn finish_dex(
    mut buf: Vec<u8>,
    sections: &mut Vec<(u16, u32, u32)>,
    data_off: usize,
    counts_and_offsets: [(u32, u32); 6],
) -> Vec<u8> {
    align(&mut buf, 4);
    let map_off = buf.len();
    sections.push((0x1000, 1, map_off as u32));
    append_u32(&mut buf, sections.len() as u32);
    for &(kind, count, offset) in sections.iter() {
        append_u16(&mut buf, kind);
        append_u16(&mut buf, 0);
        append_u32(&mut buf, count);
        append_u32(&mut buf, offset);
    }

    let file_size = buf.len();
    buf[..8].copy_from_slice(b"dex\n035\0");
    put_u32(&mut buf, 32, file_size as u32);
    put_u32(&mut buf, 36, 112);
    put_u32(&mut buf, 40, 0x1234_5678);
    put_u32(&mut buf, 44, 0);
    put_u32(&mut buf, 48, 0);
    put_u32(&mut buf, 52, map_off as u32);
    for (index, (size, off)) in counts_and_offsets.into_iter().enumerate() {
        put_u32(&mut buf, 56 + index * 8, size);
        put_u32(&mut buf, 60 + index * 8, off);
    }
    put_u32(&mut buf, 104, (file_size - data_off) as u32);
    put_u32(&mut buf, 108, data_off as u32);

    let signature = Sha1::digest(&buf[32..]);
    buf[12..32].copy_from_slice(&signature);
    let checksum = adler2::adler32_slice(&buf[12..]);
    put_u32(&mut buf, 8, checksum);
    buf
}

/// Build a small DEX with two static methods sharing one code_item.
pub fn make_dex() -> Vec<u8> {
    let strings: &[&[u8]] = &[
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"V",
        b"first",
        b"second",
        b"token",
    ];
    let mut buf = vec![0; 112];
    let mut sections = vec![(0, 1, 0)];

    let string_ids = section(&mut buf, &mut sections, 1, strings.len(), &vec![0; 4 * strings.len()], 4);
    let mut type_data = Vec::new();
    for value in [0_u32, 1, 2] {
        append_u32(&mut type_data, value);
    }
    let type_ids = section(&mut buf, &mut sections, 2, 3, &type_data, 4);
    let mut proto_data = Vec::new();
    for value in [2_u32, 2, 0] {
        append_u32(&mut proto_data, value);
    }
    let proto_ids = section(&mut buf, &mut sections, 3, 1, &proto_data, 4);
    let mut method_data = Vec::new();
    append_u16(&mut method_data, 0);
    append_u16(&mut method_data, 0);
    append_u32(&mut method_data, 3);
    append_u16(&mut method_data, 0);
    append_u16(&mut method_data, 0);
    append_u32(&mut method_data, 4);
    let method_ids = section(&mut buf, &mut sections, 5, 2, &method_data, 4);
    let class_defs = section(&mut buf, &mut sections, 6, 1, &[0; 32], 4);
    let data_off = buf.len();
    let strings_off = section(
        &mut buf,
        &mut sections,
        0x2002,
        strings.len(),
        &string_data(strings),
        1,
    );
    fill_string_ids(&mut buf, string_ids, strings, strings_off);

    let code = section(
        &mut buf,
        &mut sections,
        0x2001,
        1,
        &code_item(1, 0, 0, 3, b"\x1a\0\x05\0\x0e\0"),
        4,
    );
    let mut class_data = b"\0\0\x02\0\0\x09".to_vec();
    class_data.extend(uleb(code));
    class_data.extend_from_slice(b"\x01\x09");
    class_data.extend(uleb(code));
    let class_data = section(&mut buf, &mut sections, 0x2000, 1, &class_data, 1);

    for (index, value) in [0_u32, 1, 1, 0, u32::MAX, 0, class_data as u32, 0]
        .into_iter()
        .enumerate()
    {
        put_u32(&mut buf, class_defs + index * 4, value);
    }
    finish_dex(
        buf,
        &mut sections,
        data_off,
        [
            (strings.len() as u32, string_ids as u32),
            (3, type_ids as u32),
            (1, proto_ids as u32),
            (0, 0),
            (2, method_ids as u32),
            (1, class_defs as u32),
        ],
    )
}

/// Build one caller with repeated string references, including a CLI delimiter.
/// Target index order intentionally differs from lexical and instruction order.
pub fn make_multi_string_dex() -> Vec<u8> {
    make_member_dex(
        &[
            b"Lexample/Test;",
            b"Ljava/lang/Object;",
            b"V",
            b"run",
            b"token-z",
            b"token-a; token-b",
        ],
        &[0, 1, 2],
        None,
        &[(0, 0, 3)],
        code_item(1, 0, 0, 7, b"\x1a\0\x05\0\x1a\0\x04\0\x1a\0\x05\0\x0e\0"),
        b"\0\0\x01\0\0\x09",
    )
}

/// Build a class whose run method invokes example.Target.callToMethod.
pub fn make_invoke_dex() -> Vec<u8> {
    let strings: &[&[u8]] = &[
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"V",
        b"run",
        b"Lexample/Target;",
        b"callToMethod",
    ];
    make_member_dex(
        strings,
        &[0, 1, 2, 4],
        None,
        &[(0, 0, 3), (3, 0, 5)],
        code_item(0, 0, 0, 4, b"\x71\x00\x01\x00\x00\x00\x0e\x00"),
        b"\0\0\x01\0\0\x09",
    )
}

/// Build a class whose getA method reads this.a with iget-object.
pub fn make_instance_field_dex() -> Vec<u8> {
    let strings: &[&[u8]] = &[
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"Lexample/Target;",
        b"L",
        b"getA",
        b"a",
    ];
    make_member_dex(
        strings,
        &[0, 1, 2],
        Some(&[(0, 2, 5)]),
        &[(0, 0, 4)],
        code_item(1, 1, 0, 3, b"\x54\x00\x00\x00\x11\x00"),
        b"\x00\x01\x00\x01\x00\x01\x00\x01",
    )
}

/// Build run() with the bytecode equivalent of this.a.callToMethod().
pub fn make_field_invoke_chain_dex() -> Vec<u8> {
    let strings: &[&[u8]] = &[
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"Lexample/Target;",
        b"V",
        b"run",
        b"a",
        b"callToMethod",
    ];
    make_member_dex(
        strings,
        &[0, 1, 2, 3],
        Some(&[(0, 2, 5)]),
        &[(0, 0, 4), (2, 0, 6)],
        code_item(
            2,
            1,
            1,
            6,
            b"\x54\x10\x00\x00\x6e\x10\x01\x00\x00\x00\x0e\x00",
        ),
        b"\x00\x01\x01\x00\x00\x01\x00\x01",
    )
}

fn make_member_dex(
    strings: &[&[u8]],
    types: &[u32],
    fields: Option<&[(u16, u16, u32)]>,
    methods: &[(u16, u16, u32)],
    code_data: Vec<u8>,
    class_data_prefix: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0; 112];
    let mut sections = vec![(0, 1, 0)];
    let string_ids = section(&mut buf, &mut sections, 1, strings.len(), &vec![0; 4 * strings.len()], 4);
    let mut type_data = Vec::new();
    for &value in types {
        append_u32(&mut type_data, value);
    }
    let type_ids = section(&mut buf, &mut sections, 2, types.len(), &type_data, 4);
    let return_idx = if strings.iter().any(|value| *value == b"V") { 2 } else { 3 };
    let mut proto_data = Vec::new();
    for value in [return_idx, return_idx, 0] {
        append_u32(&mut proto_data, value);
    }
    let proto_ids = section(&mut buf, &mut sections, 3, 1, &proto_data, 4);

    let (field_ids, field_count) = if let Some(fields) = fields {
        let mut data = Vec::new();
        for &(class_idx, type_idx, name_idx) in fields {
            append_u16(&mut data, class_idx);
            append_u16(&mut data, type_idx);
            append_u32(&mut data, name_idx);
        }
        (
            section(&mut buf, &mut sections, 4, fields.len(), &data, 4) as u32,
            fields.len() as u32,
        )
    } else {
        (0, 0)
    };

    let mut method_data = Vec::new();
    for &(class_idx, proto_idx, name_idx) in methods {
        append_u16(&mut method_data, class_idx);
        append_u16(&mut method_data, proto_idx);
        append_u32(&mut method_data, name_idx);
    }
    let method_ids = section(&mut buf, &mut sections, 5, methods.len(), &method_data, 4);
    let class_defs = section(&mut buf, &mut sections, 6, 1, &[0; 32], 4);
    let data_off = buf.len();
    let strings_off = section(
        &mut buf,
        &mut sections,
        0x2002,
        strings.len(),
        &string_data(strings),
        1,
    );
    fill_string_ids(&mut buf, string_ids, strings, strings_off);
    let code = section(&mut buf, &mut sections, 0x2001, 1, &code_data, 4);
    let mut class_data = class_data_prefix.to_vec();
    class_data.extend(uleb(code));
    let class_data = section(&mut buf, &mut sections, 0x2000, 1, &class_data, 1);
    for (index, value) in [0_u32, 1, 1, 0, u32::MAX, 0, class_data as u32, 0]
        .into_iter()
        .enumerate()
    {
        put_u32(&mut buf, class_defs + index * 4, value);
    }
    finish_dex(
        buf,
        &mut sections,
        data_off,
        [
            (strings.len() as u32, string_ids as u32),
            (types.len() as u32, type_ids as u32),
            (1, proto_ids as u32),
            (field_count, field_ids),
            (methods.len() as u32, method_ids as u32),
            (1, class_defs as u32),
        ],
    )
}

/// Build a DEX whose static_values and sget field operand must agree.
pub fn make_static_field_dex() -> Vec<u8> {
    let strings: &[&[u8]] = &[
        b"Lexample/Statics;",
        b"Ljava/lang/Object;",
        b"I",
        b"FIRST",
        b"SECOND",
        b"getSecond",
    ];
    let mut buf = vec![0; 112];
    let mut sections = vec![(0, 1, 0)];
    let string_ids = section(&mut buf, &mut sections, 1, strings.len(), &vec![0; 4 * strings.len()], 4);
    let mut type_data = Vec::new();
    for value in [0_u32, 1, 2] {
        append_u32(&mut type_data, value);
    }
    let type_ids = section(&mut buf, &mut sections, 2, 3, &type_data, 4);
    let mut proto_data = Vec::new();
    for value in [2_u32, 2, 0] {
        append_u32(&mut proto_data, value);
    }
    let proto_ids = section(&mut buf, &mut sections, 3, 1, &proto_data, 4);
    let mut field_data = Vec::new();
    for &(class_idx, type_idx, name_idx) in &[(0_u16, 2_u16, 3_u32), (0, 2, 4)] {
        append_u16(&mut field_data, class_idx);
        append_u16(&mut field_data, type_idx);
        append_u32(&mut field_data, name_idx);
    }
    let field_ids = section(&mut buf, &mut sections, 4, 2, &field_data, 4);
    let mut method_data = Vec::new();
    append_u16(&mut method_data, 0);
    append_u16(&mut method_data, 0);
    append_u32(&mut method_data, 5);
    let method_ids = section(&mut buf, &mut sections, 5, 1, &method_data, 4);
    let class_defs = section(&mut buf, &mut sections, 6, 1, &[0; 32], 4);
    let data_off = buf.len();
    let strings_off = section(
        &mut buf,
        &mut sections,
        0x2002,
        strings.len(),
        &string_data(strings),
        1,
    );
    fill_string_ids(&mut buf, string_ids, strings, strings_off);
    let code = section(
        &mut buf,
        &mut sections,
        0x2001,
        1,
        &code_item(1, 0, 0, 3, b"\x60\x00\x01\x00\x0f\x00"),
        4,
    );
    let mut class_data = b"\x02\x00\x01\x00\x00\x09\x01\x09\x00\x09".to_vec();
    class_data.extend(uleb(code));
    let class_data = section(&mut buf, &mut sections, 0x2000, 1, &class_data, 1);
    let static_values = section(
        &mut buf,
        &mut sections,
        0x2005,
        1,
        b"\x02\x04\x0b\x04\x16",
        1,
    );
    for (index, value) in [
        0_u32,
        1,
        1,
        0,
        u32::MAX,
        0,
        class_data as u32,
        static_values as u32,
    ]
    .into_iter()
    .enumerate()
    {
        put_u32(&mut buf, class_defs + index * 4, value);
    }
    finish_dex(
        buf,
        &mut sections,
        data_off,
        [
            (strings.len() as u32, string_ids as u32),
            (3, type_ids as u32),
            (1, proto_ids as u32),
            (2, field_ids as u32),
            (1, method_ids as u32),
            (1, class_defs as u32),
        ],
    )
}

pub fn make_class_only_dex(descriptors: &[&str], base: usize, version: &[u8; 3]) -> Vec<u8> {
    let header_size = if version == b"041" { 0x78 } else { 0x70 };
    let encoded: Vec<&[u8]> = descriptors.iter().map(|name| name.as_bytes()).collect();
    let mut buf = vec![0; header_size];
    let string_ids = buf.len();
    buf.resize(buf.len() + 4 * encoded.len(), 0);
    let type_ids = buf.len();
    buf.resize(buf.len() + 4 * encoded.len(), 0);
    let class_defs = buf.len();
    buf.resize(buf.len() + 32 * encoded.len(), 0);
    let data_off = buf.len();

    for (index, value) in encoded.iter().enumerate() {
        let string_off = base + buf.len();
        put_u32(&mut buf, string_ids + index * 4, string_off as u32);
        put_u32(&mut buf, type_ids + index * 4, index as u32);
        for (field, field_value) in [
            index as u32,
            1,
            u32::MAX,
            0,
            u32::MAX,
            0,
            0,
            0,
        ]
        .into_iter()
        .enumerate()
        {
            put_u32(&mut buf, class_defs + index * 32 + field * 4, field_value);
        }
        buf.push(value.len() as u8);
        buf.extend_from_slice(value);
        buf.push(0);
    }

    let file_size = buf.len();
    buf[..4].copy_from_slice(b"dex\n");
    buf[4..7].copy_from_slice(version);
    put_u32(&mut buf, 0x20, file_size as u32);
    put_u32(&mut buf, 0x24, header_size as u32);
    put_u32(&mut buf, 0x28, 0x1234_5678);
    for (index, (size, off)) in [
        (encoded.len(), base + string_ids),
        (encoded.len(), base + type_ids),
        (0, 0),
        (0, 0),
        (0, 0),
        (encoded.len(), base + class_defs),
    ]
    .into_iter()
    .enumerate()
    {
        put_u32(&mut buf, 0x38 + index * 8, size as u32);
        put_u32(&mut buf, 0x3c + index * 8, off as u32);
    }
    put_u32(&mut buf, 0x68, (file_size - data_off) as u32);
    put_u32(&mut buf, 0x6c, (base + data_off) as u32);
    if version == b"041" {
        put_u32(&mut buf, 0x74, base as u32);
    }
    buf
}

pub fn make_dex041_container() -> Vec<u8> {
    let first = make_class_only_dex(&["Lalpha/First;", "Lshared/Duplicate;"], 0, b"041");
    let second = make_class_only_dex(
        &["Lbeta/Second;", "Lshared/Duplicate;"],
        first.len(),
        b"041",
    );
    let second_off = first.len();
    let mut data = first;
    data.extend(second);
    let total = data.len() as u32;
    put_u32(&mut data, 0x70, total);
    put_u32(&mut data, second_off + 0x70, total);
    data
}
