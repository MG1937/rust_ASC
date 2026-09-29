// Auth: MG1937
// dont reuse dvmopcode, the opcode regex template is gen by LLM 20260614
// opcode pattern template is gen by LLM

// bytes regex template for dex opcodes
// "" means any 1 byte
// for the listed ref opcodes here, the FIRST referenced idx starts at byte offset +2

// -----------------------------
// single-op templates
// -----------------------------

// string idx
pub const CONST_STRING: u8 = 0x1a;              // 21c: op AA BBBB
pub const CONST_STRING_JUMBO: u8 = 0x1b;        // 31c: op AA BBBBBBBB

// type idx
pub const CONST_CLASS: u8 = 0x1c;               // 21c: op AA BBBB
pub const CHECK_CAST: u8 = 0x1f;                // 21c: op AA BBBB
pub const INSTANCE_OF: u8 = 0x20;               // 22c: op BA CCCC
pub const NEW_INSTANCE: u8 = 0x22;              // 21c: op AA BBBB
pub const NEW_ARRAY: u8 = 0x23;                 // 22c: op BA CCCC
pub const FILLED_NEW_ARRAY: u8 = 0x24;          // 35c: op AG BBBB FEDC
pub const FILLED_NEW_ARRAY_RANGE: u8 = 0x25;    // 3rc: op AA BBBB CCCC

// field idx
pub const IGET: u8 = 0x52;
pub const IGET_WIDE: u8 = 0x53;
pub const IGET_OBJECT: u8 = 0x54;
pub const IGET_BOOLEAN: u8 = 0x55;
pub const IGET_BYTE: u8 = 0x56;
pub const IGET_CHAR: u8 = 0x57;
pub const IGET_SHORT: u8 = 0x58;
pub const IPUT: u8 = 0x59;
pub const IPUT_WIDE: u8 = 0x5a;
pub const IPUT_OBJECT: u8 = 0x5b;
pub const IPUT_BOOLEAN: u8 = 0x5c;
pub const IPUT_BYTE: u8 = 0x5d;
pub const IPUT_CHAR: u8 = 0x5e;
pub const IPUT_SHORT: u8 = 0x5f;

pub const SGET: u8 = 0x60;
pub const SGET_WIDE: u8 = 0x61;
pub const SGET_OBJECT: u8 = 0x62;
pub const SGET_BOOLEAN: u8 = 0x63;
pub const SGET_BYTE: u8 = 0x64;
pub const SGET_CHAR: u8 = 0x65;
pub const SGET_SHORT: u8 = 0x66;
pub const SPUT: u8 = 0x67;
pub const SPUT_WIDE: u8 = 0x68;
pub const SPUT_OBJECT: u8 = 0x69;
pub const SPUT_BOOLEAN: u8 = 0x6a;
pub const SPUT_BYTE: u8 = 0x6b;
pub const SPUT_CHAR: u8 = 0x6c;
pub const SPUT_SHORT: u8 = 0x6d;

// method idx
pub const INVOKE_VIRTUAL: u8 = 0x6e;
pub const INVOKE_SUPER: u8 = 0x6f;
pub const INVOKE_DIRECT: u8 = 0x70;
pub const INVOKE_STATIC: u8 = 0x71;
pub const INVOKE_INTERFACE: u8 = 0x72;

pub const INVOKE_VIRTUAL_RANGE: u8 = 0x74;
pub const INVOKE_SUPER_RANGE: u8 = 0x75;
pub const INVOKE_DIRECT_RANGE: u8 = 0x76;
pub const INVOKE_STATIC_RANGE: u8 = 0x77;
pub const INVOKE_INTERFACE_RANGE: u8 = 0x78;

pub const INVOKE_POLYMORPHIC: u8 = 0xfa;        // first ref is meth@BBBB at +2
pub const INVOKE_POLYMORPHIC_RANGE: u8 = 0xfb;  // first ref is meth@BBBB at +2

// call_site idx
pub const INVOKE_CUSTOM: u8 = 0xfc;
pub const INVOKE_CUSTOM_RANGE: u8 = 0xfd;

// method_handle idx
pub const CONST_METHOD_HANDLE: u8 = 0xfe;

// proto idx
pub const CONST_METHOD_TYPE: u8 = 0xff;
// note:
// fa/fb also contain proto@HHHH, but that is NOT the first ref idx, so not covered by simple prefix+idx template

// -----------------------------
// grouped opcode classes
// -----------------------------

use crate::asc_core::findrefs::locator::insn_locator::InsnLocator;
use std::collections::{HashMap, HashSet};

use lazy_static::lazy_static;
use regex::bytes::Regex;

lazy_static! {
    // \x1a const-string \x1b const-string/jumbo
    pub static ref STRINGIDX_OPS: Regex = Regex::new(r"[\x1a\x1b]").unwrap();

    pub static ref TYPEIDX_OPS: Regex = Regex::new(r"[\x1c\x1f\x20\x22\x23\x24\x25]").unwrap();

    pub static ref INSTANCE_FIELDIDX_OPS: Regex = Regex::new(r"[\x52-\x5f]").unwrap();

    pub static ref STATIC_FIELDIDX_OPS: Regex = Regex::new(r"[\x60-\x6d]").unwrap();

    pub static ref FIELDIDX_OPS: Regex = Regex::new(r"[\x52-\x6d]").unwrap();

    pub static ref METHODIDX_OPS: Regex = Regex::new(r"[\x6e-\x72\x74-\x78\xfa\xfb]").unwrap();

    // for dex038+, such insn are used very infrequently, so we just ignore it for now... 20260617
    pub static ref CALLSITEIDX_OPS: Regex = Regex::new(r"[\xfc-\xfd]").unwrap();

    pub static ref METHODHANDLEIDX_OPS: Regex = Regex::new(r"\xfe").unwrap();

    pub static ref PROTOIDX_OPS: Regex = Regex::new(r"\xff").unwrap();
    // fa/fb second proto idx cannot be expressed as OP + "" + idx directly
}

lazy_static! {
    pub static ref OPCODE_PATTERNS: HashMap<&'static str, &'static Regex> = {
        let mut m = HashMap::new();
        m.insert("method", &*METHODIDX_OPS);
        m.insert("field", &*FIELDIDX_OPS);
        m.insert("type", &*TYPEIDX_OPS);
        m
    };
}

struct _STRUCT_I;
impl _STRUCT_I {
    fn unpack_from(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
    }
}

struct _STRUCT_H;
impl _STRUCT_H {
    fn unpack_from(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([buf[off], buf[off+1]])
    }
}

// scan type -> tuple of (opcode byte values, referenced idx width in bytes)
// the referenced idx always starts two bytes after its opcode byte
fn _idx_groups(idx_type: &str) -> &[(&[u8], usize)] {
    const FIELD_BYTES: &[u8] = &[0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                                  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d];
    const METHOD_BYTES: &[u8] = &[0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xfa, 0xfb];
    const TYPE_BYTES: &[u8] = &[0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25];
    match idx_type {
        "string" => &[(&[0x1a], 2usize), (&[0x1b], 4usize)],
        "type" => &[(TYPE_BYTES, 2usize)],
        "field" => &[(FIELD_BYTES, 2usize)],
        "method" => &[(METHOD_BYTES, 2usize)],
        _ => &[],
    }
}

const _ANY_BYTE: &str = r"[\x00-\xff]";
const _CLASS_SPECIAL: &[u8] = b"\\]^-[";

fn _escape_class_byte(value: u8) -> String {
    if _CLASS_SPECIAL.contains(&value) {
        format!("\\x{:02x}", value)
    } else {
        format!("\\x{:02x}", value)
    }
}

fn _byte_class(values: &[u8]) -> String {
    // compact regex character class matching exactly the given byte values
    let mut values: Vec<u8> = values.to_vec();
    values.sort();
    values.dedup();
    let total = values.len();
    if total == 256 {
        return _ANY_BYTE.to_string();
    }
    let mut out = String::from("[");
    let mut index = 0;
    while index < total {
        let mut last = index;
        while last + 1 < total && values[last + 1] == values[last] + 1 {
            last += 1;
        }
        if last - index >= 2 {
            out.push_str(&_escape_class_byte(values[index]));
            out.push('-');
            out.push_str(&_escape_class_byte(values[last]));
        } else {
            for pos in index..=last {
                out.push_str(&_escape_class_byte(values[pos]));
            }
        }
        index = last + 1;
    }
    out.push(']');
    out
}

fn _build_scan_pattern(opcode_class: &str, _idx_width: usize, _idxs: &HashSet<u32>) -> Regex {
    // Rust's regex crate does not support look-ahead, so we cannot use the Python
    // pre-filter approach. Instead, match the opcode class directly; survivors
    // are checked exactly by the caller below.
    Regex::new(&format!(r"(?s-u){}", opcode_class)).unwrap()
}

// CPython compiles a one character class to a literal and scans for it with memchr
// (measured 0.47 ns/byte); with two or more characters it falls back to the regex VM
// loop (3.5-6.5 ns/byte), which the translate prefilter below beats outright. So the
// switch is at two opcodes: the string type's two single-opcode groups keep the regex,
// every other class (7 type, 12 method, 28 field opcodes) uses the prefilter.
// Measured on a 3.21MB code region, regex vs prefilter: field 20.0 vs 10.1ms (-50%),
// method 10.4 vs 8.3ms (-20%), type 20.5 vs 18.1ms (-12%), string 3.0 vs 10.6ms.
//
// NOTE: Rust's regex crate does NOT support look-ahead, so the regex path without
// pre-filter is significantly slower. Force all groups to use dense scan instead.
const _DENSE_OPCODE_COUNT: usize = 1;

fn _mask_table(values: &[u8]) -> [u8; 256] {
    // 256 entry 0/1 table used by the dense scan below
    let mut table = [0u8; 256];
    for &v in values {
        table[v as usize] = 1;
    }
    table
}

fn _hi_mask(idxs: &HashSet<u32>) -> [u8; 256] {
    let mut table = [0u8; 256];
    for &idx in idxs {
        table[((idx >> 8) & 0xff) as usize] = 1;
    }
    table
}

pub struct CodeItemScanner<'a> {
    // when we decide to scan code item, means we already build up the insn locator
    pub off_start: u32,
    pub off_end: u32,
    pub buf: &'a [u8],
    pub submem: &'a [u8],
    pub mark_idx: Vec<u32>,
}

impl<'a> CodeItemScanner<'a> {
    pub fn new(insn_locator: &InsnLocator<'a>) -> Self {
        let off_start = insn_locator.code_item_start;
        let off_end = insn_locator.code_item_end;
        let buf = insn_locator.base.buf;
        CodeItemScanner {
            off_start,
            off_end,
            buf,
            submem: &buf[off_start as usize .. off_end as usize],
            mark_idx: Vec::new(),
        }
    }

    // dense opcode classes: memchr pre-filter replaces the Python bytes.translate
    // approach. For 1-4 opcode values, memchr uses SIMD internally. For larger sets
    // (field=28, method=12, type=7) fall back to mask-table loop.
    // The exact idx check below still runs on every survivor.
    fn _scan_code_item_dense(&self, opcode_values: &[u8], idxs: &HashSet<u32>, idx_width: usize, mark: bool, matched_offset: &mut Vec<u32>, mark_idx: &mut Vec<u32>) {
        let off_start = self.off_start as usize;
        let raw = self.submem;
        let raw_len = raw.len();
        if raw_len < 4 { return; }

        let check_idx = |start: usize| -> Option<u32> {
            if start + 2 + idx_width > raw_len { return None; }
            let idx = if idx_width == 2 {
                u16::from_le_bytes([raw[start + 2], raw[start + 3]]) as u32
            } else {
                u32::from_le_bytes([raw[start + 2], raw[start + 3], raw[start + 4], raw[start + 5]])
            };
            if idxs.contains(&idx) { Some(idx) } else { None }
        };

        match opcode_values.len() {
            1 => {
                let op = opcode_values[0];
                for start in memchr::memchr_iter(op, raw) {
                    if let Some(idx) = check_idx(start) {
                        matched_offset.push((start + off_start) as u32);
                        if mark { mark_idx.push(idx); }
                    }
                }
            }
            2 => {
                let (a, b) = (opcode_values[0], opcode_values[1]);
                for start in memchr::memchr2_iter(a, b, raw) {
                    if let Some(idx) = check_idx(start) {
                        matched_offset.push((start + off_start) as u32);
                        if mark { mark_idx.push(idx); }
                    }
                }
            }
            3 => {
                let (a, b, c) = (opcode_values[0], opcode_values[1], opcode_values[2]);
                for start in memchr::memchr3_iter(a, b, c, raw) {
                    if let Some(idx) = check_idx(start) {
                        matched_offset.push((start + off_start) as u32);
                        if mark { mark_idx.push(idx); }
                    }
                }
            }
            _ => {
                // >3 opcode values: mask-table loop, still use hi_mask pre-filter for speed
                let op_mask = _mask_table(opcode_values);
                for start in 0..raw_len.saturating_sub(3) {
                    if op_mask[raw[start] as usize] == 0 { continue; }
                    if start + 2 + idx_width > raw_len { continue; }
                    let idx = if idx_width == 2 {
                        u16::from_le_bytes([raw[start + 2], raw[start + 3]]) as u32
                    } else {
                        u32::from_le_bytes([raw[start + 2], raw[start + 3], raw[start + 4], raw[start + 5]])
                    };
                    if !idxs.contains(&idx) { continue; }
                    matched_offset.push((start + off_start) as u32);
                    if mark { mark_idx.push(idx); }
                }
            }
        }
    }

    // if mark is True, record correspond idx for offset
    fn _scan_code_item(&mut self, idx_type: &str, idxs: &HashSet<u32>, mark: bool) -> Vec<u32> {
        let off_start = self.off_start as usize;
        let submem = self.submem;
        let mut matched_offset = Vec::new();
        let mut mark_idx = Vec::new();
        self.mark_idx = Vec::new(); // reset, will reassign below

        let groups = _idx_groups(idx_type);
        for &(opcode_values, idx_width) in groups {
            if opcode_values.len() >= _DENSE_OPCODE_COUNT {
                // Use opcode_values directly for dense scan instead of regex
                self._scan_code_item_dense(opcode_values, idxs, idx_width, mark, &mut matched_offset, &mut mark_idx);
                continue;
            }
            let pattern = _build_scan_pattern(&_byte_class(opcode_values), idx_width, idxs);
            for match_ in pattern.find_iter(submem) {
                let start = match_.start();
                // bounds check: need at least start + 2 + idx_width bytes
                if start + 2 + idx_width > submem.len() {
                    continue;
                }
                // the idx bytes were prefiltered in regex, the exact value still
                // decides whether this opcode really references a target idx
                let idx = if idx_width == 2 {
                    _STRUCT_H::unpack_from(submem, start + 2) as u32
                } else {
                    _STRUCT_I::unpack_from(submem, start + 2)
                };
                if !idxs.contains(&idx) {
                    continue;
                }
                matched_offset.push((start + off_start) as u32);
                if mark {
                    mark_idx.push(idx);
                }
            }
        }

        if groups.len() > 1 {
            // separate scans per idx width break offset order, restore it
            let mut indices: Vec<usize> = (0..matched_offset.len()).collect();
            indices.sort_by_key(|&i| matched_offset[i]);
            let sorted_matched_offset: Vec<u32> = indices.iter().map(|&i| matched_offset[i]).collect();
            matched_offset.clear();
            matched_offset.extend(sorted_matched_offset);
            if mark {
                let sorted_mark_idx: Vec<u32> = indices.iter().map(|&i| mark_idx[i]).collect();
                mark_idx.clear();
                mark_idx.extend(sorted_mark_idx);
            }
        }

        self.mark_idx = mark_idx;
        matched_offset
    }

    // scan struct: {"string": {idx1, idx2...}, "field": ...,}
    // only handle with string idx, field idx, method idx, type idx
    // others such as proto, methodhandle is too FUCKING wired, leave it for now.. 20260617
    pub fn scan(&mut self, scan: &mut HashMap<String, Vec<Option<Vec<u32>>>>, mark: bool, insn_locator: &mut InsnLocator<'a>) {
        let type_keys: Vec<String> = scan.keys().cloned().collect();
        for type_key in type_keys {
            if !scan.get(&type_key).map(|v| !v.is_empty()).unwrap_or(false) {
                scan.insert(type_key, Vec::new());
                continue;
            }
            // Convert Vec<Option<Vec<u32>>> to flat HashSet<u32> for scanning
            let idxs_set: HashSet<u32> = scan[&type_key].iter()
                .filter_map(|entry| entry.as_ref())
                .flatten()
                .copied()
                .collect();
            let insn_offs = self._scan_code_item(&type_key, &idxs_set, mark);
            let mids = insn_locator.locate(&insn_offs);
            scan.insert(type_key, mids);
        }
    }
}
