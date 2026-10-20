// Auth: MG1937

// r8 using MUTF8 to handle string payload,
// so 0x00 will be encoded to 0xC0 0x80

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::utils::structs::_STRUCT_I;
use crate::asc_core::utils::tinydex::{DEX, _decode_mutf8_fallback};
use memchr::memmem::Finder;
use std::collections::HashSet;
use std::time::Instant;

fn matches_name(raw: &[u8], query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    if !query.is_ascii() || !raw.is_ascii() {
        return _decode_mutf8_fallback(raw).to_lowercase().contains(query);
    }
    let pattern = query.as_bytes();
    memchr::memchr2_iter(
        pattern[0].to_ascii_lowercase(),
        pattern[0].to_ascii_uppercase(),
        raw,
    )
    .any(|start| {
        raw.get(start..start + pattern.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(pattern))
    })
}

pub struct StringLocator<'a> {
    pub base: BaseLocator<'a>,
    pub stridx_map: Vec<u64>, // [(string_data_off << 32) | string_idx, ...]
    pub strdata_start: u32,
    pub strdata_end: u32,
    pub parsed: bool,
}

impl<'a> StringLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        StringLocator {
            base: BaseLocator::new(dex),
            stridx_map: Vec::new(),
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
        stridx_map.reserve(string_ids_size as usize + 1);
        let buf = self.base.buf;
        if string_ids_size == 0 {
            self.parsed = true;
            self._debug_log("build_map", t_start, Some(0));
            return;
        }
        let string_ids_end = string_ids_off
            .checked_add(string_ids_size as usize * 4)
            .unwrap_or(usize::MAX);
        if string_ids_end > buf.len() {
            self.parsed = true;
            self._debug_log("build_map", t_start, Some(0));
            return;
        }
        // might buggy.. r8 not specify the first string data off is the begging of all string data off, but usually it was...
        let Some(strdata_start) = _STRUCT_I::try_unpack_from(buf, string_ids_off) else {
            self.parsed = true;
            self._debug_log("build_map", t_start, Some(0));
            return;
        };
        self.strdata_start = strdata_start;
        let mut data_offset = 0u32;
        for idx in 0..string_ids_size {
            data_offset = _STRUCT_I::try_unpack_from(buf, string_ids_off).unwrap();
            string_ids_off += 4;
            if data_offset as usize >= buf.len() {
                self.stridx_map.clear();
                self.strdata_start = 0;
                self.parsed = true;
                self._debug_log("build_map", t_start, Some(0));
                return;
            }
            stridx_map.push(((data_offset as u64) << 32) | idx as u64);
        }
        // Include the final string_data_item. The existing lookup maps a
        // match through the following string offset, so add an end sentinel
        // for the final item without changing that mapping scheme.
        let mut end = data_offset as usize;
        while end < buf.len() && buf[end] & 0x80 != 0 {
            end += 1;
        }
        let Some(payload_start) = end.checked_add(1).filter(|&offset| offset <= buf.len()) else {
            self.stridx_map.clear();
            self.strdata_start = 0;
            self.parsed = true;
            self._debug_log("build_map", t_start, Some(0));
            return;
        };
        let Some(relative_end) = buf[payload_start..]
            .iter()
            .position(|&byte| byte == 0)
        else {
            self.stridx_map.clear();
            self.strdata_start = 0;
            self.parsed = true;
            self._debug_log("build_map", t_start, Some(0));
            return;
        };
        self.strdata_end = (payload_start + relative_end + 1) as u32;
        stridx_map.push(((self.strdata_end as u64) << 32) | string_ids_size as u64);
        stridx_map.sort_unstable();
        self.parsed = true;
        let count = stridx_map.len();
        self._debug_log("build_map", t_start, Some(count));
    }

    fn _match_string_offset(&self, string: &str) -> HashSet<u32> {
        let buf = self.base.buf;
        let strdata_start = self.strdata_start as usize;
        let strdata_end = self.strdata_end as usize;
        if strdata_start > strdata_end || strdata_end > buf.len() {
            return HashSet::new();
        }
        let submem = &buf[strdata_start..strdata_end];

        let finder = Finder::new(string.as_bytes());
        let stridx_map = &self.stridx_map;
        let mut located_idx = HashSet::new();
        let mut last_offset = usize::MAX;

        for match_ in finder.find_iter(submem) {
            let mut offset = strdata_start + match_ + string.len();
            // find null terminator after the match
            if offset < strdata_end {
                let slice = &buf[offset..strdata_end];
                if let Some(null_rel) = memchr::memchr(0, slice) {
                    offset = offset + null_rel + 1; // skip over 00 byte
                    if offset == last_offset {
                        continue;
                    }
                    last_offset = offset;
                    let key = (offset as u64) << 32;
                    let pos = stridx_map.partition_point(|&entry| entry < key);
                    if pos < stridx_map.len() && stridx_map[pos] >> 32 == offset as u64 {
                        if let Some(idx) = (stridx_map[pos] as u32).checked_sub(1) {
                            located_idx.insert(idx);
                        }
                    }
                }
            }
        }
        located_idx
    }

    /// Match each distinct method-name index once, regardless of physical string order.
    pub(crate) fn locate_name_indices(
        buf: &[u8],
        name_indices: impl Iterator<Item = u32>,
        query: &str,
    ) -> Result<HashSet<u32>, String> {
        if buf.len() < 0x70 {
            return Err("invalid DEX header".to_owned());
        }
        let count = _STRUCT_I::unpack_from(buf, 0x38) as usize;
        let offset = _STRUCT_I::unpack_from(buf, 0x3c) as usize;
        let end = count
            .checked_mul(4)
            .and_then(|size| offset.checked_add(size))
            .ok_or("DEX string table overflow")?;
        if end > buf.len() {
            return Err("DEX string table outside input".to_owned());
        }
        let query = query.to_lowercase();
        let mut seen = vec![false; count];
        let mut matches = HashSet::new();
        for index in name_indices {
            let index_usize = index as usize;
            let visited = seen
                .get_mut(index_usize)
                .ok_or("DEX string index out of range")?;
            if *visited {
                continue;
            }
            *visited = true;
            let data = _STRUCT_I::unpack_from(buf, offset + index_usize * 4) as usize;
            let raw = Self::string_data_bytes(buf, data)?;
            if matches_name(raw, &query) {
                matches.insert(index);
            }
        }
        Ok(matches)
    }

    pub(crate) fn string_data_bytes(buf: &[u8], mut offset: usize) -> Result<&[u8], String> {
        for shift in (0..35).step_by(7) {
            let byte = *buf.get(offset).ok_or("truncated DEX string length")?;
            offset += 1;
            if shift == 28 && byte > 0x0f {
                return Err("DEX string length overflow".to_owned());
            }
            if byte & 0x80 == 0 {
                let tail = &buf[offset..];
                let end = memchr::memchr(0, tail).ok_or("unterminated DEX string")?;
                return Ok(&tail[..end]);
            }
        }
        Err("DEX string length overflow".to_owned())
    }

    pub fn locate(&self, string: &str) -> HashSet<u32> {
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        // Note: _build_map needs &mut self but locate takes &self
        // The caller must ensure _build_map is called before locate
        let located_idx = self._match_string_offset(string);
        self._debug_log("locate", t_start, Some(located_idx.len()));
        located_idx
    }
}
