// Auth: MG1937

// DONT PARSE IT, JUST FUCKING MATCH IT!!!!!
// VERY FKING FAST!
pub fn read_uleb128_fast(data: &[u8], pos: usize) -> (u64, usize) {
    let b = data[pos];
    if b < 128 {
        return (b as u64, 1);
    }
    
    let mut res = (b & 0x7f) as u64;
    let b = data[pos + 1];
    res |= ((b & 0x7f) as u64) << 7;
    if b < 128 { return (res, 2); }
    
    let b = data[pos + 2];
    res |= ((b & 0x7f) as u64) << 14;
    if b < 128 { return (res, 3); }
    
    let b = data[pos + 3];
    res |= ((b & 0x7f) as u64) << 21;
    if b < 128 { return (res, 4); }
    
    let b = data[pos + 4];
    res |= ((b & 0x7f) as u64) << 28;
    (res, 5)
}

pub fn write_uleb128(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if value == 0 {
        return vec![0x00];
    }
    while value > 0x7f {
        out.push(((value & 0x7f) | 0x80) as u8);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

pub fn read_sleb128(data: &[u8], pos: usize) -> (i64, usize) {
    let mut result: i64 = 0;
    let mut shift = 0;
    let start = pos;
    let mut pos = pos;
    loop {
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            if shift < 32 && (byte & 0x40) != 0 {
                result |= -(1i64 << shift);
            }
            return (result, pos - start);
        }
    }
}

pub fn write_sleb128(mut value: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        let more = !((value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0));
        if more {
            byte |= 0x80;
        }
        out.push(byte);
        if !more {
            break;
        }
    }
    out
}

pub fn read_uleb128_len(data: &[u8], pos: usize) -> usize {
    if data[pos] < 128 { return 1; }
    if data[pos + 1] < 128 { return 2; }
    if data[pos + 2] < 128 { return 3; }
    if data[pos + 3] < 128 { return 4; }
    if data[pos + 4] < 128 { return 5; }
    let mut p = pos + 5;
    while data[p] >= 128 {
        p += 1;
    }
    p - pos + 1
}