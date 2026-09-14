// Auth MG1937

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::models::dvm_opcode::opcodes;
use crate::asc_core::utils::leb128::{read_uleb128_fast, read_uleb128_len};
use crate::asc_core::utils::tinydex::DEX;
use std::collections::HashMap;
use std::time::Instant;

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

// verify that bytes from start to end form a valid sequence of instructions
// used as a secondary check after bucket-based lookup to avoid false positives
pub fn insn_verify(buf: &[u8], start: usize, end: usize) -> bool {
    let mut pos = start;
    while pos < end {
        if pos >= buf.len() {
            return false;
        }
        let opcode_byte = buf[pos];
        match opcodes.get(&opcode_byte) {
            Some(op) => {
                let insn_len = (op.oplen as usize) * 2;
                if insn_len == 0 {
                    return false;
                }
                pos += insn_len;
            }
            None => return false,
        }
    }
    pos == end
}

// +-----------------+
// | codeitem header | <-- register_size, ins_size... MUST hold 16 bytes!
// +-----------------+
// |  insn (ushort)  | <-- at least 1 insn, which hold 2 bytes!
// +-----------------+
// | codeitem header |
// |       ...       |
// Each method's insn starts at codeitem offset + 16 (header size)
// Use insn_off >> 4 as bucket key
// methods are naturally bucketed.
// For methods spanning multiple buckets,
// fill all buckets from start to end. Achieves O(1) lookup.

// cover insn offset to method idx
pub struct InsnLocator<'a> {
    pub base: BaseLocator<'a>,
    pub parsed: bool,
    // use 16 bytes dense table to achieve O(1) speed
    pub insn_maps: HashMap<u32, Vec<u32>>, // {insn_off_bucket: [midx, midx2...]}
    pub code_item_start: u32, // fuzzy offset around 16 bytes
    pub code_item_end: u32, // fuzzy too

    // for insn verify... bugfix for insn mismatch 20260728
    pub method_bounds: HashMap<u32, u32>, // {midx: insn_off_start}
}

impl<'a> InsnLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        let mut locator = InsnLocator {
            base: BaseLocator::new(dex),
            parsed: false,
            insn_maps: HashMap::new(),
            code_item_start: 0,
            code_item_end: 0,
            method_bounds: HashMap::new(),
        };
        locator
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.base.set_debug(debug);
    }

    pub fn _debug_log(&self, stage: &str, t_start: Option<Instant>, count: Option<usize>) {
        _debug_log("InsnLocator", stage, t_start, count, self.base.debug);
    }

    pub fn _encoded_method_parse(&mut self, data: &[u8], pos: u32, midx: u32) {
        if pos == 0 {
            // code off == 0 means no method body, we dont need to locate it, ignore
            return;
        }
        let insn_size = _STRUCT_I::unpack_from(data, pos as usize + 12);
        let insn_off = pos + 16;
        let insn_maps = &mut self.insn_maps;
        // need to declare why do this... checkout the diagram in file head
        let insn_bucket_start = insn_off >> 4;
        let insn_bucket_end = (insn_off + insn_size * 2 - 1) >> 4;

        self.method_bounds.insert(midx, insn_off);

        // R8 insn deduplicate machenism, different method may refer to same insn body
        let bucket_entry = insn_maps.get(&insn_bucket_start).cloned();
        let resolved_midxs = match bucket_entry {
            Some(old) => {
                let mut v = vec![midx];
                v.extend(old);
                v
            }
            None => vec![midx],
        };

        for i in insn_bucket_start..=insn_bucket_end {
            insn_maps.insert(i, resolved_midxs.clone());
        }
    }

    // return next class data item pos
    pub fn _class_data_parse(&mut self, data: &[u8], mut pos: u32) -> u32 {
        // reuse tinydex logic
        let (static_fields_size, c) = read_uleb128_fast(data, pos as usize);
        pos += c as u32;
        let (instance_fields_size, c) = read_uleb128_fast(data, pos as usize);
        pos += c as u32;
        let (direct_methods_size, c) = read_uleb128_fast(data, pos as usize);
        pos += c as u32;
        let (virtual_methods_size, c) = read_uleb128_fast(data, pos as usize);
        pos += c as u32;

        for _ in 0..(static_fields_size + instance_fields_size) as u32 {
            pos += read_uleb128_len(data, pos as usize) as u32;
            pos += read_uleb128_len(data, pos as usize) as u32;
        }

        let mut method_idx: u32 = 0;
        for _ in 0..direct_methods_size {
            let (method_idx_diff, c) = read_uleb128_fast(data, pos as usize);
            pos += c as u32;
            method_idx += method_idx_diff as u32;
            pos += read_uleb128_len(data, pos as usize) as u32;
            let (code_off, c) = read_uleb128_fast(data, pos as usize);
            pos += c as u32;
            self._encoded_method_parse(data, code_off as u32, method_idx);
        }

        method_idx = 0;
        for _ in 0..virtual_methods_size {
            let (method_idx_diff, c) = read_uleb128_fast(data, pos as usize);
            pos += c as u32;
            method_idx += method_idx_diff as u32;
            pos += read_uleb128_len(data, pos as usize) as u32;
            let (code_off, c) = read_uleb128_fast(data, pos as usize);
            pos += c as u32;
            self._encoded_method_parse(data, code_off as u32, method_idx);
        }
        pos
    }

    pub fn _build_map_bymap(&mut self) {
        if self.parsed {
            return;
        }
        // dont reuse tinydex, frequent lazy parser may cause bad performance
        // parse all items in one shot by map!
        let buf = self.base.buf;
        let mapoff = self.base.dex.header.mapoff as usize;
        let mapsize = _STRUCT_I::unpack_from(buf, mapoff);
        let mut mapoff = mapoff + 4;
        let mut mtype: u16 = 0;
        for _ in 0..mapsize {
            mtype = _STRUCT_H::unpack_from(buf, mapoff);
            if mtype == 0x2000 {
                break;
            }
            mapoff += 0xc;
        }
        if mtype != 0x2000 {
            self._build_map_bydef();
            return;
        }

        // skip type + unused
        let class_data_size = u32::from_le_bytes([buf[mapoff + 4], buf[mapoff + 5], buf[mapoff + 6], buf[mapoff + 7]]);
        let mut class_data_off = u32::from_le_bytes([buf[mapoff + 8], buf[mapoff + 9], buf[mapoff + 10], buf[mapoff + 11]]);
        for _ in 0..class_data_size {
            class_data_off = self._class_data_parse(buf, class_data_off);
        }
    }

    pub fn _build_map_bydef(&mut self) {
        if self.parsed {
            return;
        }
        let (class_def_off, class_def_size) = self.base.dex.header.classes;
        let mut class_def_off = class_def_off as usize;
        let buf = self.base.buf;
        for _ in 0..class_def_size {
            let class_data_off = _STRUCT_I::unpack_from(buf, class_def_off + 24);
            class_def_off += 0x20;
            if class_data_off == 0 {
                continue;
            }
            self._class_data_parse(buf, class_data_off);
        }
    }

    pub fn parse(&mut self) {
        if self.parsed {
            return;
        }
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        self._build_map_bymap();
        if !self.insn_maps.is_empty() {
            let keys: Vec<&u32> = self.insn_maps.keys().collect();
            let min_key = **keys.iter().min().unwrap();
            let max_key = **keys.iter().max().unwrap();
            self.code_item_start = min_key << 4;
            self.code_item_end = (max_key + 1) << 4;
        }
        self.parsed = true;
        self._debug_log("parse", t_start, Some(self.insn_maps.len()));
    }

    // insn offset to method idx, warn: midx can be None or list
    pub fn locate(&mut self, offsets: &[u32]) -> Vec<Option<Vec<u32>>> {
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        if !self.parsed {
            // parse timing controlled by manager
            return Vec::new();
        }
        let mut ret_table: Vec<Option<Vec<u32>>> = Vec::with_capacity(offsets.len());
        let insn_maps = &self.insn_maps;
        let buf = self.base.buf;
        let method_bounds = &mut self.method_bounds;

        for &off in offsets {
            let bucket = off >> 4;
            let midx_option = insn_maps.get(&bucket);

            match midx_option {
                Some(midxs) if !midxs.is_empty() => {
                    let first_midx = midxs[0];
                    if let Some(&start_off) = method_bounds.get(&first_midx) {
                        if insn_verify(buf, start_off as usize, off as usize) {
                            ret_table.push(Some(midxs.clone()));
                            method_bounds.insert(first_midx, off);
                        } else {
                            ret_table.push(None);
                        }
                    } else {
                        ret_table.push(None);
                    }
                }
                _ => {
                    ret_table.push(None);
                }
            }
        }

        // dense table is fuzzy, insn range verify back to method verify stage! 20260617
        self._debug_log("locate", t_start, Some(ret_table.len()));
        ret_table
    }
}