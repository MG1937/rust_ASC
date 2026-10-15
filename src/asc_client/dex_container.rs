// Auth: MG1937
// Strict 1:1 translation from Python dex_container.py

const _DEX_HEADER_MIN_SIZE: usize = 0x70;
const _DEX041_MAGIC: &[u8] = b"dex\n041\x00";

fn _u32_from(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Check whether data is a DEX041 container
pub fn is_dex041_container(data: &[u8]) -> bool {
    data.len() >= _DEX_HEADER_MIN_SIZE && data[..8] == *_DEX041_MAGIC
}

/// Get offsets of all logical DEX entries in a DEX041 container
pub fn dex041_logical_offsets(data: &[u8]) -> Vec<usize> {
    if !is_dex041_container(data) {
        return vec![0];
    }
    let mut offsets = Vec::new();
    let mut off = 0;
    let data_len = data.len();
    while off + _DEX_HEADER_MIN_SIZE <= data_len && data[off..off + 8] == *_DEX041_MAGIC {
        let file_size = _u32_from(data, off + 0x20) as usize;
        if file_size < _DEX_HEADER_MIN_SIZE || off + file_size > data_len {
            break;
        }
        offsets.push(off);
        off += file_size;
    }
    if offsets.is_empty() {
        vec![0]
    } else {
        offsets
    }
}

fn _patch_u32(buf: &mut [u8], off: usize, delta: u32) {
    let val = _u32_from(buf, off);
    if val != 0 && val != 0xFFFFFFFF && val >= delta {
        let new_val = val - delta;
        buf[off..off + 4].copy_from_slice(&new_val.to_le_bytes());
    }
}

fn _read_uleb128(buf: &[u8], off: usize) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut pos = off;
    loop {
        let b = buf[pos];
        pos += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b < 0x80 {
            return (result, pos - off);
        }
        shift += 7;
    }
}

fn _write_uleb128(value: u64) -> Vec<u8> {
    let mut value = value;
    let mut out = Vec::new();
    while value > 0x7F {
        out.push(((value & 0x7F) | 0x80) as u8);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

fn _patch_uleb128_in_place(buf: &mut [u8], off: usize, delta: u64) -> usize {
    let (value, size) = _read_uleb128(buf, off);
    if value == 0 || value < delta {
        return size;
    }
    let new_data = _write_uleb128(value - delta);
    if new_data.len() != size {
        // DEX041 keeps physical offsets. In practice subtracting the container
        // base can shrink a uleb128. Avoid shifting the whole DEX here; leave it
        // untouched rather than corrupting following fields.
        return size;
    }
    buf[off..off + size].copy_from_slice(&new_data);
    size
}

/// Normalize a logical DEX from a DEX041 container (copy header to file start)
pub fn normalize_dex041_logical(data: &[u8], header_off: usize) -> Vec<u8> {
    if header_off == 0 {
        return data.to_vec();
    }
    let header_size = _u32_from(data, header_off + 0x24) as usize;
    let header_size = if header_size < _DEX_HEADER_MIN_SIZE || header_off + header_size > data.len() {
        _DEX_HEADER_MIN_SIZE
    } else {
        header_size
    };
    let mut out = data.to_vec();
    out[..header_size].copy_from_slice(&data[header_off..header_off + header_size]);
    out
}

fn _patch_class_data_code_offsets(buf: &mut [u8], class_defs_off: usize, class_defs_size: usize, delta: u64) {
    for class_idx in 0..class_defs_size {
        let class_def_off = class_defs_off + class_idx * 32;
        if class_def_off + 32 > buf.len() {
            break;
        }
        let class_data_off = _u32_from(buf, class_def_off + 24) as usize;
        if class_data_off == 0 || class_data_off >= buf.len() {
            continue;
        }
        let mut p = class_data_off;
        let (static_fields_size, n) = _read_uleb128(buf, p);
        p += n;
        let (instance_fields_size, n) = _read_uleb128(buf, p);
        p += n;
        let (direct_methods_size, n) = _read_uleb128(buf, p);
        p += n;
        let (virtual_methods_size, n) = _read_uleb128(buf, p);
        p += n;
        for _ in 0..static_fields_size + instance_fields_size {
            let (_, n) = _read_uleb128(buf, p);
            p += n;
            let (_, n) = _read_uleb128(buf, p);
            p += n;
        }
        for _ in 0..direct_methods_size + virtual_methods_size {
            let (_, n) = _read_uleb128(buf, p);
            p += n;
            let (_, n) = _read_uleb128(buf, p);
            p += n;
            p += _patch_uleb128_in_place(buf, p, delta);
        }
    }
}

fn _patch_code_item_debug_offsets(buf: &mut [u8], delta: u32) {
    let map_off = _u32_from(buf, 0x34) as usize;
    if !(0 < map_off + 4 && map_off + 4 <= buf.len()) {
        return;
    }
    let map_size = _u32_from(buf, map_off) as usize;
    let mut p = map_off + 4;
    let mut code_off = 0usize;
    let mut code_size = 0usize;
    for _ in 0..map_size {
        if p + 12 > buf.len() {
            return;
        }
        let typ = u16::from_le_bytes([buf[p], buf[p + 1]]);
        let size = _u32_from(buf, p + 4) as usize;
        let off = _u32_from(buf, p + 8) as usize;
        if typ == 0x2001 {
            code_size = size;
            code_off = off;
            break;
        }
        p += 12;
    }
    p = code_off;
    for _ in 0..code_size {
        if p + 16 > buf.len() {
            break;
        }
        _patch_u32(buf, p + 8, delta);
        let insns_size = _u32_from(buf, p + 12) as usize;
        let tries_size = u16::from_le_bytes([buf[p + 6], buf[p + 7]]);
        p = p + 16 + insns_size * 2;
        if tries_size != 0 {
            if p & 3 != 0 {
                p += 2;
            }
            p += tries_size as usize * 8;
            // encoded_catch_handler_list is variable length. Use the next code
            // item alignment from map only as best effort is not available here.
            // Existing code paths only need debug_off fixed before bytecode read.
        }
        while p & 3 != 0 {
            p += 1;
        }
    }
}

/// Iterate all logical DEX buffers in a DEX041 container
pub fn iter_logical_dex_buffers(name: &str, data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let offsets = dex041_logical_offsets(data);
    if offsets.len() <= 1 {
        return vec![(name.to_string(), data.to_vec())];
    }
    let mut result = Vec::with_capacity(offsets.len());
    for (idx, &header_off) in offsets.iter().enumerate() {
        let logical_name = format!("{}!classes{}.dex", name, idx + 1);
        result.push((logical_name, normalize_dex041_logical(data, header_off)));
    }
    result
}

pub fn into_logical_dex_buffers(name: &str, data: Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let offsets = dex041_logical_offsets(&data);
    if offsets.len() <= 1 {
        return vec![(name.to_string(), data)];
    }
    let mut result = Vec::with_capacity(offsets.len());
    for (idx, &header_off) in offsets.iter().enumerate() {
        let logical_name = format!("{}!classes{}.dex", name, idx + 1);
        result.push((logical_name, normalize_dex041_logical(&data, header_off)));
    }
    result
}