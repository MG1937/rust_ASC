// Auth: MG1937

// r8 using MUTF8 to handle string payload,
// so 0x00 will be encoded to 0xC0 0x80

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::utils::tinydex::DEX;
use std::collections::HashSet;
use std::time::Instant;

struct _STRUCT_I;
impl _STRUCT_I {
    fn unpack_from(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
    }
}

pub struct StringLocator<'a> {
    pub base: BaseLocator<'a>,
    pub stridx_map: std::collections::HashMap<u32, u32>, // {string_data_off : string_idx}
    pub strdata_start: u32,
    pub strdata_end: u32,
    pub parsed: bool,
}

impl<'a> StringLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        StringLocator {
            base: BaseLocator::new(dex),
            stridx_map: std::collections::HashMap::new(),
            strdata_start: 0,
            strdata_end: 0,
            parsed: false,
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.base.set_debug(debug);
    }

    pub fn _debug_log(&self, stage: &str, t_start: Option<Instant>, count: Option<usize>) {
        _debug_log("StringLocator", stage, t_start, count, self.base.debug);
    }

    pub fn _build_map(&mut self) {
        if self.parsed {
            return;
        }
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        let (string_ids_off, string_ids_size) = self.base.dex.header.strings;
        let mut string_ids_off = string_ids_off as usize;
        let stridx_map = &mut self.stridx_map;
        let buf = self.base.buf;
        // might buggy.. r8 not specify the first string data off is the begging of all string data off, but usually it was...
        self.strdata_start = _STRUCT_I::unpack_from(buf, string_ids_off);
        let mut data_offset = 0u32;
        for idx in 0..string_ids_size {
            data_offset = _STRUCT_I::unpack_from(buf, string_ids_off);
            string_ids_off += 4;
            stridx_map.insert(data_offset, idx);
        }
        self.strdata_end = data_offset;
        self.parsed = true;
        let count = stridx_map.len();
        self._debug_log("build_map", t_start, Some(count));
    }

    fn _match_string_offset(&self, string: &str) -> Vec<u32> {
        let buf = self.base.buf;
        let strdata_start = self.strdata_start as usize;
        let strdata_end = self.strdata_end as usize;
        let submem = &buf[strdata_start..strdata_end];

        let pattern = regex::bytes::Regex::new(string).unwrap();
        let mut results = Vec::new();

        for match_ in pattern.find_iter(submem) {
            let mut offset = strdata_start + match_.end();
            // find null terminator after the match
            if offset < strdata_end {
                let slice = &buf[offset..strdata_end];
                if let Some(null_rel) = slice.iter().position(|&b| b == 0) {
                    offset = offset + null_rel;
                    results.push((offset + 1) as u32); // skip over 00 byte
                }
            }
        }
        results
    }

    pub fn locate(&self, string: &str) -> HashSet<u32> {
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        // Note: _build_map needs &mut self but locate takes &self
        // The caller must ensure _build_map is called before locate
        let stridx_map = &self.stridx_map;
        let mut located_idx = HashSet::new();
        for offset in self._match_string_offset(string) {
            if let Some(&idx) = stridx_map.get(&offset) {
                located_idx.insert(idx - 1);
            }
        }
        self._debug_log("locate", t_start, Some(located_idx.len()));
        located_idx
    }
}