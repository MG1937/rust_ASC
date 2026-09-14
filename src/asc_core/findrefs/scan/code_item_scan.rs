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
// \x1a const-string  \x1b const-string/jumbo
// type idx
// \x1c const-class, \x1f check-cast, \x20 instance-of, \x22 new-instance, \x23 new-array, \x24 filled-new-array, \x25 filled-new-array/range
// field idx
// \x52-\x5f iget/iput variants, \x60-\x6d sget/sput variants
// method idx
// \x6e-\x72 invoke-virtual/super/direct/static/interface, \x74-\x78 invoke-*/range, \xfa\xfb invoke-polymorphic
// call_site idx
// \xfc-\xfd invoke-custom, invoke-custom/range
// method_handle idx
// \xfe const-method-handle
// proto idx
// \xff const-method-type

use crate::asc_core::findrefs::locator::insn_locator::InsnLocator;
use std::collections::HashSet;

use lazy_static::lazy_static;
use regex::bytes::Regex;

lazy_static! {
    static ref STRINGIDX_OPS: Regex = Regex::new(r"[\x1a\x1b]").unwrap();
    static ref TYPEIDX_OPS: Regex = Regex::new(r"[\x1c\x1f\x20\x22\x23\x24\x25]").unwrap();
    static ref INSTANCE_FIELDIDX_OPS: Regex = Regex::new(r"[\x52-\x5f]").unwrap();
    static ref STATIC_FIELDIDX_OPS: Regex = Regex::new(r"[\x60-\x6d]").unwrap();
    static ref FIELDIDX_OPS: Regex = Regex::new(r"[\x52-\x6d]").unwrap();
    static ref METHODIDX_OPS: Regex = Regex::new(r"[\x6e-\x72\x74-\x78\xfa\xfb]").unwrap();
    // for dex038+, such insn are used very infrequently, so we just ignore it for now... 20260617
    static ref CALLSITEIDX_OPS: Regex = Regex::new(r"[\xfc-\xfd]").unwrap();
    static ref METHODHANDLEIDX_OPS: Regex = Regex::new(r"\xfe").unwrap();
    static ref PROTOIDX_OPS: Regex = Regex::new(r"\xff").unwrap();
    // fa/fb second proto idx cannot be expressed as OP + "" + idx directly
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

pub struct CodeItemScanner<'a> {
    // when we decide to scan code item, means we already build up the insn locator
    pub off_start: u32,
    pub off_end: u32,
    pub buf: &'a [u8],
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
            mark_idx: Vec::new(),
        }
    }

    fn submem(&self) -> &[u8] {
        &self.buf[self.off_start as usize .. self.off_end as usize]
    }

    // if mark is True, record correspond idx for offset
    pub fn _scan_code_item(&mut self, idx_type: &str, idxs: &HashSet<u32>, mark: bool) -> Vec<u32> {
        let off_start = self.off_start as usize;
        let submem = self.submem();
        let buf_len = submem.len();
        let mut matched_offset = Vec::new();
        let mut mark_idx = Vec::new();

        if idx_type == "string" {
            for match_ in STRINGIDX_OPS.find_iter(submem) {
                // buggy, might have oob issue 20260617
                let idx_off = match_.start() + 2;
                let idx = if match_.as_bytes()[0] == 0x1a {
                    // const-string
                    if (idx_off + 2) > buf_len {
                        // bugfix for oob, dont use try-except, bad performance.. 20260729
                        self.mark_idx = mark_idx;
                        return matched_offset;
                    }
                    _STRUCT_H::unpack_from(submem, idx_off) as u32
                } else {
                    // const-string/jumbo
                    if (idx_off + 4) > buf_len {
                        self.mark_idx = mark_idx;
                        return matched_offset;
                    }
                    _STRUCT_I::unpack_from(submem, idx_off)
                };
                if !idxs.contains(&idx) {
                    continue;
                }
                matched_offset.push((idx_off + off_start - 2) as u32);
                if mark {
                    mark_idx.push(idx);
                }
            }
            self.mark_idx = mark_idx;
            return matched_offset;
        } else {
            let pattern = match idx_type {
                "method" => &*METHODIDX_OPS,
                "field" => &*FIELDIDX_OPS,
                "type" => &*TYPEIDX_OPS,
                _ => return matched_offset,
            };
            for match_ in pattern.find_iter(submem) {
                // buggy, might have oob issue 20260617
                let idx_off = match_.start() + 2;
                if (idx_off + 2) > buf_len {
                    self.mark_idx = mark_idx;
                    return matched_offset;
                }
                let idx = _STRUCT_H::unpack_from(submem, idx_off) as u32;
                if !idxs.contains(&idx) {
                    continue;
                }
                matched_offset.push((idx_off + off_start - 2) as u32);
                if mark {
                    mark_idx.push(idx);
                }
            }
            self.mark_idx = mark_idx;
            return matched_offset;
        }
    }

    // scan struct: {"string": {idx1, idx2...}, "field": ...,}
    // only handle with string idx, field idx, method idx, type idx
    // others such as proto, methodhandle is too FUCKING wired, leave it for now.. 20260617
    pub fn scan(&mut self, scan: &mut std::collections::HashMap<String, Vec<u32>>, mark: bool, insn_locator: &mut InsnLocator<'a>) {
        let keys: Vec<String> = scan.keys().cloned().collect();
        for type_key in keys {
            let idxs_set: HashSet<u32> = match scan.get(&type_key) {
                Some(v) if !v.is_empty() => v.iter().cloned().collect(),
                _ => {
                    scan.insert(type_key, Vec::new());
                    continue;
                }
            };
            let insn_offs = self._scan_code_item(&type_key, &idxs_set, mark);
            let mids = insn_locator.locate(&insn_offs);
            // flatten locate result to Vec<u32>
            let mut flat_mids = Vec::new();
            for entry in mids {
                if let Some(mid_list) = entry {
                    for &mid in &mid_list {
                        if !flat_mids.contains(&mid) {
                            flat_mids.push(mid);
                        }
                    }
                }
            }
            scan.insert(type_key, flat_mids);
        }
    }
}