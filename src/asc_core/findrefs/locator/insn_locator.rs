// Auth MG1937

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::models::dvm_opcode::opcodes;
use crate::asc_core::utils::leb128::{read_uleb128_fast, read_uleb128_len};
use crate::asc_core::utils::tinydex::DEX;
use std::time::Instant;

const _EMPTY_BUCKET: u32 = 0;
const _SHARED_BUCKET: u32 = 1 << 31;

struct _STRUCT_I;
impl _STRUCT_I {
    fn unpack_from(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }
}

struct _STRUCT_H;
impl _STRUCT_H {
    fn unpack_from(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([buf[off], buf[off + 1]])
    }
}

// verify that bytes from start to end form a valid sequence of instructions
// used as a secondary check after bucket-based lookup to avoid false positives
// python ASC use regex for native insn verify speed up, we dont need it in rust
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
//
// 20260930 change O(1) bucket struct, use dense table instead of hashmap, more faster
// The code_off in encoded_method caps at 0xFFFF_FFFF. So the dense table's theoretical max is that >> 4, roughly 1GB.
// In practice R8 enforces a 0xFFFF+1 method ceiling. Hitting the code_off cap would require every method to
// hold 30k+ instructions (2 bytes each, ignoring extra structure between methods), which never happens.
// I counted instruction counts across most APKs: over 70% of methods have fewer than 20 instructions.
// Meanwhile Google's DEX code optimization wants each dex around 10MB max,
// so even in the worst case the real dense table lands near 10MB >> 4, about 600KB.
// https://developer.android.com/google/play/vitals/code-optimization
//
// also tried on python ASC, bascially no optimization,
// likely because py dict is already native and can't be optimized further,
// while Rust's HashMap is heavy, so switching structures pays off.

// cover insn offset to method idx
pub struct InsnLocator<'a> {
    pub base: BaseLocator<'a>,
    pub parsed: bool,
    // Dense 16-byte bucket table. 0 is empty, midx + 1 is a single method,
    // and the high bit refers to an entry in insn_shared.
    pub insn_maps: Vec<u32>, // [slot, ...], slot = 0 / midx + 1 / (_SHARED_BUCKET | shared_idx)
    pub insn_maps_build: Vec<(u32, u32, u32)>, // [(bucket_start, bucket_end, midx), ...]
    pub insn_shared: Vec<Vec<u32>>, // [[midx, midx2, ...], ...]
    pub insn_bucket_base: u32, // insn_maps[insn_bucket - insn_bucket_base]
    pub code_item_start: u32, // fuzzy offset around 16 bytes
    pub code_item_end: u32,  // fuzzy too

    // for insn verify... bugfix for insn mismatch 20260728
    pub method_bounds: Vec<u32>, // method_bounds[midx] = insn_off_start
    pub max_midx: usize,
}

impl<'a> InsnLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        let mut locator = InsnLocator {
            base: BaseLocator::new(dex),
            parsed: false,
            insn_maps: Vec::new(),
            insn_maps_build: Vec::new(),
            insn_shared: Vec::new(),
            insn_bucket_base: 0,
            code_item_start: 0,
            code_item_end: 0,
            method_bounds: vec![0; dex.header.methods.1 as usize],
            max_midx: 0,
        };
        locator
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.base.set_debug(debug);
    }

    pub fn _debug_log(&self, stage: &str, t_start: Option<Instant>, count: Option<usize>) {
        _debug_log("InsnLocator", stage, t_start, count, self.base.debug);
    }

    #[inline(always)]
    pub fn _encoded_method_parse(&mut self, data: &[u8], pos: u32, midx: u32) {
        if pos == 0 {
            // code off == 0 means no method body, we dont need to locate it, ignore
            return;
        }
        let insn_size = _STRUCT_I::unpack_from(data, pos as usize + 12);
        let insn_off = pos + 16;
        // need to declare why do this... checkout the diagram in file head
        let insn_bucket_start = insn_off >> 4;
        let insn_bucket_end = (insn_off + insn_size * 2 - 1) >> 4;

        self.method_bounds[midx as usize] = insn_off;
        self.max_midx = self.max_midx.max(midx as usize);
        self.insn_maps_build
            .push((insn_bucket_start, insn_bucket_end, midx));
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

        for method_size in [direct_methods_size, virtual_methods_size] {
            let mut method_idx: u32 = 0;
            for _ in 0..method_size {
                let (method_idx_diff, c) = read_uleb128_fast(data, pos as usize);
                pos += c as u32;
                method_idx += method_idx_diff as u32;
                let (_, c) = read_uleb128_fast(data, pos as usize);
                pos += c as u32;
                let (code_off, c) = read_uleb128_fast(data, pos as usize);
                pos += c as u32;
                self._encoded_method_parse(data, code_off as u32, method_idx);
            }
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
        if mapoff == 0 || mapoff + 4 > buf.len() {
            self._build_map_bydef();
            return;
        }
        let mapsize = _STRUCT_I::unpack_from(buf, mapoff);
        let mut mapoff = mapoff + 4;
        let mut mtype: u16 = 0;
        for _ in 0..mapsize {
            if mapoff + 12 > buf.len() {
                break;
            }
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
        let class_data_size = u32::from_le_bytes([
            buf[mapoff + 4],
            buf[mapoff + 5],
            buf[mapoff + 6],
            buf[mapoff + 7],
        ]);
        let mut class_data_off = u32::from_le_bytes([
            buf[mapoff + 8],
            buf[mapoff + 9],
            buf[mapoff + 10],
            buf[mapoff + 11],
        ]);
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
        let t_start = if self.base.debug {
            Some(Instant::now())
        } else {
            None
        };
        self._build_map_bymap();
        if !self.insn_maps_build.is_empty() {
            let min_bucket = self
                .insn_maps_build
                .iter()
                .map(|(start, _, _)| *start)
                .min()
                .unwrap();
            let max_bucket = self
                .insn_maps_build
                .iter()
                .map(|(_, end, _)| *end)
                .max()
                .unwrap();
            self.insn_bucket_base = min_bucket;
            self.insn_maps = vec![_EMPTY_BUCKET; (max_bucket - min_bucket + 1) as usize];

            for &(start, end, midx) in &self.insn_maps_build {
                let start_index = (start - min_bucket) as usize;
                let resolved = match self.insn_maps[start_index] {
                    _EMPTY_BUCKET => midx + 1,
                    slot if slot & _SHARED_BUCKET == 0 => {
                        let shared_index = self.insn_shared.len() as u32;
                        self.insn_shared.push(vec![midx, slot - 1]);
                        _SHARED_BUCKET | shared_index
                    }
                    slot => {
                        let old = &self.insn_shared[(slot & !_SHARED_BUCKET) as usize];
                        let mut methods = Vec::with_capacity(old.len() + 1);
                        methods.extend_from_slice(old);
                        methods.push(midx);
                        let shared_index = self.insn_shared.len() as u32;
                        self.insn_shared.push(methods);
                        _SHARED_BUCKET | shared_index
                    }
                };
                self.insn_maps[(start - min_bucket) as usize..=(end - min_bucket) as usize]
                    .fill(resolved);
            }
            self.insn_maps_build.clear();
            self.code_item_start = min_bucket << 4;
            self.code_item_end = (max_bucket + 1) << 4;
        }
        self.parsed = true;
        let mapped_count = if self.base.debug {
            self.insn_maps
                .iter()
                .filter(|&&slot| slot != _EMPTY_BUCKET)
                .count()
        } else {
            0
        };
        self._debug_log("parse", t_start, Some(mapped_count));
    }

    // insn offset to method idx, warn: midx can be None or list
    pub fn locate(&mut self, offsets: &[u32]) -> Vec<Option<Vec<u32>>> {
        let t_start = if self.base.debug {
            Some(Instant::now())
        } else {
            None
        };
        if !self.parsed {
            // parse timing controlled by manager
            return Vec::new();
        }
        let mut ret_table: Vec<Option<Vec<u32>>> = Vec::with_capacity(offsets.len());
        let insn_maps = &self.insn_maps;
        let buf = self.base.buf;
        let mut method_bounds = vec![0u32; self.max_midx + 1];

        for &off in offsets {
            let bucket = off >> 4;
            let slot = bucket
                .checked_sub(self.insn_bucket_base)
                .and_then(|index| insn_maps.get(index as usize))
                .copied()
                .unwrap_or(_EMPTY_BUCKET);

            match slot {
                _EMPTY_BUCKET => ret_table.push(None),
                slot => {
                    let first_midx = if slot & _SHARED_BUCKET == 0 {
                        slot - 1
                    } else {
                        self.insn_shared[(slot & !_SHARED_BUCKET) as usize][0]
                    };
                    let first_midx = first_midx as usize;
                    let start_off = if method_bounds[first_midx] != 0 {
                        method_bounds[first_midx]
                    } else {
                        self.method_bounds[first_midx]
                    };
                    if start_off != 0 && insn_verify(buf, start_off as usize, off as usize) {
                        let midxs = if slot & _SHARED_BUCKET == 0 {
                            vec![slot - 1]
                        } else {
                            self.insn_shared[(slot & !_SHARED_BUCKET) as usize].clone()
                        };
                        ret_table.push(Some(midxs));
                        method_bounds[first_midx] = off;
                    } else {
                        ret_table.push(None);
                    }
                }
            }
        }

        // dense table is fuzzy, insn range verify back to method verify stage! 20260617
        self._debug_log("locate", t_start, Some(ret_table.len()));
        ret_table
    }
}
