// Auth: MG1937
// Strict 1:1 translation from Python apk/dex_reader.py

use crate::asc_core::utils::structs::_STRUCT_I;
use crate::asc_core::utils::tinydex::_decode_mutf8_fallback;

fn _skip_uleb128(buf: &[u8], mut off: usize) -> Result<usize, String> {
    while *buf
        .get(off)
        .ok_or_else(|| "bad string_data_off".to_owned())?
        & 0x80
        != 0
    {
        off += 1;
    }
    Ok(off + 1)
}

fn _read_string_data_bytes(buf: &[u8], str_off: usize) -> Result<&[u8], String> {
    // The leading uleb128 stores UTF-16 code-unit count, not byte length.
    // Reading to the terminating NUL is therefore required for MUTF-8.
    let ptr = _skip_uleb128(buf, str_off)?;
    let raw = buf
        .get(ptr..)
        .ok_or_else(|| "bad string_data_off".to_owned())?;
    let end = memchr::memchr(0, raw).ok_or_else(|| "unterminated string_data_item".to_owned())?;
    Ok(&raw[..end])
}

fn _find_type_idx(buf: &[u8], target_bytes: &[u8]) -> Result<i32, String> {
    if buf.len() < 0x70 || buf[..3] != *b"dex" {
        return Ok(-1);
    }

    let string_ids_size = _STRUCT_I::unpack_from(buf, 0x38) as usize;
    let string_ids_off = _STRUCT_I::unpack_from(buf, 0x3C) as usize;
    let type_ids_size = _STRUCT_I::unpack_from(buf, 0x40) as usize;
    let type_ids_off = _STRUCT_I::unpack_from(buf, 0x44) as usize;

    if string_ids_size == 0 || type_ids_size == 0 {
        return Ok(-1);
    }
    if string_ids_off + string_ids_size * 4 > buf.len() {
        return Err("bad string_ids range".to_owned());
    }
    if type_ids_off + type_ids_size * 4 > buf.len() {
        return Err("bad type_ids range".to_owned());
    }

    let mut left = 0i32;
    let mut right = type_ids_size as i32 - 1;
    // type_ids follows string-id order. DEX MUTF-8 bytes preserve UTF-16
    // code-unit ordering, so compare encoded descriptors without decoding.
    while left <= right {
        let mid = ((left + right) >> 1) as usize;
        let str_idx = _STRUCT_I::unpack_from(buf, type_ids_off + (mid << 2)) as usize;
        if str_idx >= string_ids_size {
            return Err("bad type_id->string_idx".to_owned());
        }
        let str_off = _STRUCT_I::unpack_from(buf, string_ids_off + (str_idx << 2)) as usize;
        if str_off >= buf.len() {
            return Err("bad string_data_off".to_owned());
        }

        let cls_bytes = _read_string_data_bytes(buf, str_off)?;
        match cls_bytes.cmp(target_bytes) {
            std::cmp::Ordering::Equal => return Ok(mid as i32),
            std::cmp::Ordering::Less => left = mid as i32 + 1,
            std::cmp::Ordering::Greater => right = mid as i32 - 1,
        }
    }

    Ok(-1)
}

fn _class_defs_contains_type_idx(buf: &[u8], type_idx: u32) -> Result<bool, String> {
    let class_defs_size = _STRUCT_I::unpack_from(buf, 0x60) as usize;
    let class_defs_off = _STRUCT_I::unpack_from(buf, 0x64) as usize;

    if class_defs_size == 0 {
        return Ok(false);
    }

    let class_defs_end = class_defs_off + (class_defs_size << 5);
    if class_defs_end > buf.len() {
        return Err("bad class_defs range".to_owned());
    }

    let needle = type_idx.to_le_bytes();
    let mut pos = class_defs_off;
    while let Some(found) = memchr::memmem::find(&buf[pos..class_defs_end], &needle) {
        pos += found;
        // The same four bytes may occur in another class_def field. class_idx
        // is valid only at the first word of each 32-byte class_def_item.
        if ((pos - class_defs_off) & 0x1F) == 0 {
            return Ok(true);
        }
        pos += 1;
    }
    Ok(false)
}

pub(crate) fn _dex_defines_class(buf: &[u8], target_bytes: &[u8]) -> Result<bool, String> {
    let type_idx = _find_type_idx(buf, target_bytes)?;
    if type_idx < 0 {
        return Ok(false);
    }
    _class_defs_contains_type_idx(buf, type_idx as u32)
}

fn _decode_name(raw_name: &[u8]) -> String {
    match std::str::from_utf8(raw_name) {
        Ok(name) => name.to_owned(),
        // Surrogate-pair MUTF-8 is invalid strict UTF-8. In the Python code
        // this import is lazy; Rust's fallback is already available here.
        Err(_) => _decode_mutf8_fallback(raw_name),
    }
}

pub(crate) fn list_dex_classes(
    buf: &[u8],
    prefix: Option<&str>,
    prefix_bytes: Option<&[u8]>,
) -> Result<Vec<String>, String> {
    if buf.len() < 0x70 || buf[..3] != *b"dex" {
        return Err("invalid DEX header".to_owned());
    }

    let string_ids_size = _STRUCT_I::unpack_from(buf, 0x38) as usize;
    let string_ids_off = _STRUCT_I::unpack_from(buf, 0x3C) as usize;
    let type_ids_size = _STRUCT_I::unpack_from(buf, 0x40) as usize;
    let type_ids_off = _STRUCT_I::unpack_from(buf, 0x44) as usize;
    let class_defs_size = _STRUCT_I::unpack_from(buf, 0x60) as usize;
    let class_defs_off = _STRUCT_I::unpack_from(buf, 0x64) as usize;

    if class_defs_size == 0 {
        return Ok(Vec::new());
    }
    if string_ids_off + string_ids_size * 4 > buf.len() {
        return Err("bad string_ids range".to_owned());
    }
    if type_ids_off + type_ids_size * 4 > buf.len() {
        return Err("bad type_ids range".to_owned());
    }
    if class_defs_off + class_defs_size * 32 > buf.len() {
        return Err("bad class_defs range".to_owned());
    }

    let mut names = Vec::new();
    let class_defs_end = class_defs_off + class_defs_size * 32;
    for class_def_off in (class_defs_off..class_defs_end).step_by(32) {
        let type_idx = _STRUCT_I::unpack_from(buf, class_def_off) as usize;
        if type_idx >= type_ids_size {
            return Err("bad class_def->type_idx".to_owned());
        }
        let string_idx = _STRUCT_I::unpack_from(buf, type_ids_off + (type_idx << 2)) as usize;
        if string_idx >= string_ids_size {
            return Err("bad type_id->string_idx".to_owned());
        }
        let string_off = _STRUCT_I::unpack_from(buf, string_ids_off + (string_idx << 2)) as usize;
        if string_off >= buf.len() {
            return Err("bad string_data_off".to_owned());
        }
        let raw_name = _read_string_data_bytes(buf, string_off)
            .map_err(|_| "bad string_data_off".to_owned())?;

        // ASCII prefixes can be rejected before decoding every class name.
        if let Some(prefix_bytes) = prefix_bytes {
            if raw_name.starts_with(prefix_bytes) {
                names.push(_decode_name(raw_name));
            }
        } else {
            let name = _decode_name(raw_name);
            if prefix.is_none_or(|prefix| name.starts_with(prefix)) {
                names.push(name);
            }
        }
    }
    Ok(names)
}
