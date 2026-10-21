// Auth: MG1937
// Strict 1:1 translation from Python apk/dex_reader.py

use crate::asc_core::findrefs::locator::string_locator::matches_name;
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

/// Smallest DEX prefix that contains every class descriptor string.
///
/// R8/D8 emit `class_defs` before the data section, so the id tables pin down
/// each descriptor's `string_data_off`; only those strings (plus a NUL) need to
/// be decompressed to list class names.
/// Smallest DEX prefix that can answer "does this DEX define `target`?".
///
/// The answer needs only the id tables plus the descriptor string; code items,
/// debug info and class_data are irrelevant. A class lookup therefore inflates
/// ~10-30% of each DEX it rejects instead of the whole file.
pub(crate) fn class_defines_prefix_len(buf: &[u8], target: &[u8]) -> Result<usize, String> {
    const SLACK: usize = 1024;
    if buf.len() < 0x70 {
        return Ok(0x70);
    }
    if buf[..3] != *b"dex" {
        // Not a DEX prefix we can reason about; ask for everything.
        return Ok(buf.len().saturating_add(SLACK));
    }
    let string_ids_size = _STRUCT_I::unpack_from(buf, 0x38) as usize;
    let string_ids_off = _STRUCT_I::unpack_from(buf, 0x3C) as usize;
    let type_ids_size = _STRUCT_I::unpack_from(buf, 0x40) as usize;
    let type_ids_off = _STRUCT_I::unpack_from(buf, 0x44) as usize;
    let class_defs_size = _STRUCT_I::unpack_from(buf, 0x60) as usize;
    let class_defs_off = _STRUCT_I::unpack_from(buf, 0x64) as usize;

    let tables_end = string_ids_off
        .saturating_add(string_ids_size * 4)
        .max(type_ids_off.saturating_add(type_ids_size * 4))
        .max(class_defs_off.saturating_add(class_defs_size * 32));
    if buf.len() < tables_end {
        return Ok(tables_end);
    }

    let Ok(type_idx) = _find_type_idx(buf, target) else {
        return Ok(buf.len().saturating_add(SLACK));
    };
    if type_idx < 0 {
        // Descriptor absent: the id tables alone already give the answer.
        return Ok(tables_end);
    }
    let string_idx = _STRUCT_I::unpack_from(buf, type_ids_off + (type_idx as usize) * 4) as usize;
    if string_idx >= string_ids_size {
        return Ok(tables_end);
    }
    let string_off = _STRUCT_I::unpack_from(buf, string_ids_off + (string_idx << 2)) as usize;
    match _read_string_data_bytes(buf, string_off) {
        Ok(raw) => {
            let start = raw.as_ptr() as usize - buf.as_ptr() as usize;
            Ok((start + raw.len() + 1).max(tables_end))
        }
        Err(_) => Ok(buf.len().saturating_add(SLACK)),
    }
}

pub(crate) fn class_names_prefix_len(buf: &[u8]) -> Result<usize, String> {
    const SLACK: usize = 4096;
    if buf.len() < 0x70 {
        return Ok(0x70);
    }
    if buf[..3] != *b"dex" {
        return Err("invalid DEX header".to_owned());
    }
    let string_ids_size = _STRUCT_I::unpack_from(buf, 0x38) as usize;
    let string_ids_off = _STRUCT_I::unpack_from(buf, 0x3C) as usize;
    let type_ids_size = _STRUCT_I::unpack_from(buf, 0x40) as usize;
    let type_ids_off = _STRUCT_I::unpack_from(buf, 0x44) as usize;
    let class_defs_size = _STRUCT_I::unpack_from(buf, 0x60) as usize;
    let class_defs_off = _STRUCT_I::unpack_from(buf, 0x64) as usize;

    // Probe one string_data offset before requesting the complete id tables.
    // A late string pool is a hint that prefix decoding will be expensive. Ask
    // for the full entry early so the loader's existing fallback can restart
    // after only a header-sized probe, rather than redoing all of the id tables.
    // Physical string order is not guaranteed by DEX: this is only a choice of
    // decoder, never an assumption used to omit classes or validate an offset.
    if string_ids_size != 0 {
        let first_id_end = string_ids_off
            .checked_add(4)
            .ok_or_else(|| "bad string_ids range".to_owned())?;
        if buf.len() < first_id_end {
            return Ok(first_id_end);
        }
        let first_data_off = _STRUCT_I::unpack_from(buf, string_ids_off) as u64;
        let file_size = _STRUCT_I::unpack_from(buf, 0x20) as u64;
        if first_data_off < file_size && first_data_off * 5 > file_size * 3 {
            return Ok(usize::MAX);
        }
    }

    let Some(id_end) = class_defs_off.checked_add(class_defs_size * 32) else {
        return Ok(buf.len());
    };
    let tables_end = id_end
        .max(string_ids_off.saturating_add(string_ids_size * 4))
        .max(type_ids_off.saturating_add(type_ids_size * 4));
    if buf.len() < tables_end {
        return Ok(tables_end);
    }

    let descriptor_off = |class_index: usize| -> Option<usize> {
        let class_off = class_defs_off + class_index * 32;
        let type_idx = _STRUCT_I::unpack_from(buf, class_off) as usize;
        if type_idx >= type_ids_size {
            return None;
        }
        let string_idx = _STRUCT_I::unpack_from(buf, type_ids_off + (type_idx << 2)) as usize;
        if string_idx >= string_ids_size {
            return None;
        }
        Some(_STRUCT_I::unpack_from(buf, string_ids_off + (string_idx << 2)) as usize)
    };

    let mut max_start = tables_end;
    for class_index in 0..class_defs_size {
        if let Some(offset) = descriptor_off(class_index) {
            max_start = max_start.max(offset);
        }
    }
    if buf.len() < max_start.saturating_add(SLACK) {
        return Ok(max_start.saturating_add(SLACK));
    }

    let mut max_end = max_start.saturating_add(1);
    for class_index in 0..class_defs_size {
        let Some(offset) = descriptor_off(class_index) else {
            continue;
        };
        match _read_string_data_bytes(buf, offset) {
            Ok(raw) => {
                let start = raw.as_ptr() as usize - buf.as_ptr() as usize;
                max_end = max_end.max(start + raw.len() + 1);
            }
            // The terminator is past the current prefix; ask for more.
            Err(_) => return Ok(buf.len().saturating_add(SLACK)),
        }
    }
    Ok(max_end)
}

pub(crate) fn write_dex_class_names(
    buf: &[u8],
    prefix: Option<&str>,
    prefix_bytes: Option<&[u8]>,
    out: &mut Vec<u8>,
) -> Result<usize, String> {
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
        return Ok(0);
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

    let start_len = out.len();
    let mut count = 0usize;
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
            if !raw_name.starts_with(prefix_bytes) {
                continue;
            }
        }
        let name = std::str::from_utf8(raw_name);
        match name {
            Ok(name) => {
                if prefix.is_some() && prefix_bytes.is_none() && !name.starts_with(prefix.unwrap()) {
                    continue;
                }
                out.reserve(name.len() + 1);
                out.extend_from_slice(name.as_bytes());
            }
            Err(_) => {
                let name = _decode_name(raw_name);
                if prefix.is_some_and(|prefix| !name.starts_with(prefix)) {
                    continue;
                }
                out.reserve(name.len() + 1);
                out.extend_from_slice(name.as_bytes());
            }
        }
        out.push(b'\n');
        count += 1;
    }
    let _ = start_len;
    Ok(count)
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

/// Walk the string pool in table order, handing every value that passes
/// `filter` to `sink`. String index is what a `findrefs` row resolves through,
/// so table order is the only order this reports.
fn for_each_dex_string<S>(buf: &[u8], filter: Option<&str>, mut sink: S) -> Result<usize, String>
where
    S: FnMut(&str) -> Result<(), String>,
{
    if buf.len() < 0x70 || buf[..3] != *b"dex" {
        return Err("invalid DEX header".to_owned());
    }

    let string_ids_size = _STRUCT_I::unpack_from(buf, 0x38) as usize;
    let string_ids_off = _STRUCT_I::unpack_from(buf, 0x3C) as usize;
    if string_ids_size == 0 {
        return Ok(0);
    }
    let ids_end = string_ids_off
        .checked_add(string_ids_size.saturating_mul(4))
        .filter(|&end| end <= buf.len())
        .ok_or_else(|| "bad string_ids range".to_owned())?;

    let mut count = 0;
    let mut off = string_ids_off;
    while off < ids_end {
        let string_off = _STRUCT_I::unpack_from(buf, off) as usize;
        off += 4;
        if string_off >= buf.len() {
            return Err("bad string_data_off".to_owned());
        }
        let raw = _read_string_data_bytes(buf, string_off)?;
        if !filter.is_none_or(|filter| matches_name(raw, filter)) {
            continue;
        }
        sink(&_decode_name(raw))?;
        count += 1;
    }
    Ok(count)
}

/// Write string values one per line, skipping the ones `filter` rejects.
/// `list_dex_strings` is the record level API that keeps embedded newlines.
pub(crate) fn write_dex_strings(
    buf: &[u8],
    filter: Option<&str>,
    out: &mut Vec<u8>,
) -> Result<usize, String> {
    for_each_dex_string(buf, filter, |value| {
        out.reserve(value.len() + 1);
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
        Ok(())
    })
}

pub(crate) fn list_dex_strings(buf: &[u8], filter: Option<&str>) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for_each_dex_string(buf, filter, |value| {
        values.push(value.to_owned());
        Ok(())
    })?;
    Ok(values)
}
