// Auth: MG1937

// r8 using MUTF8 to handle string payload,
// so 0x00 will be encoded to 0xC0 0x80

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::utils::structs::_STRUCT_I;
use crate::asc_core::utils::tinydex::{DEX, _decode_mutf8_fallback};
use memchr::memmem::Finder;
use std::collections::HashSet;
use std::time::Instant;

/// Case insensitive substring match over a raw string_data_item payload.
/// Shared with `liststring` so both agree on what the filter matches; `query`
/// is expected to be lowercased by the caller.
pub(crate) fn matches_name(raw: &[u8], query: &str) -> bool {
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
        // string_data_item order is independent of string_ids order, so take the
        // physical bounds from the table instead of assuming index 0 is first.
        let mut min_offset = u32::MAX;
        let mut max_offset = 0u32;
        for idx in 0..string_ids_size {
            let data_offset = _STRUCT_I::try_unpack_from(buf, string_ids_off).unwrap();
            string_ids_off += 4;
            if data_offset as usize >= buf.len() {
                self.stridx_map.clear();
                self.strdata_start = 0;
                self.parsed = true;
                self._debug_log("build_map", t_start, Some(0));
                return;
            }
            min_offset = min_offset.min(data_offset);
            max_offset = max_offset.max(data_offset);
            stridx_map.push(((data_offset as u64) << 32) | idx as u64);
        }
        self.strdata_start = min_offset;
        let mut end = max_offset as usize;
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
        let mut last_idx = u32::MAX;

        for match_ in finder.find_iter(submem) {
            // fix issue for https://github.com/MG1937/rust_ASC/issues/8
            // 20261023
            // str idx order is independent of str data off
            // str_idx0 -> 0x100 ; 0x100 off = aaa
            // str_idx1 -> 0x300 ; 0x200 off = bbb
            // str_idx2 -> 0x200 ; 0x300 off = ccc
            // old logic will try to match string from str data area, assume we match bbb
            // and should get str_idx2, but old logic assume str idx order is related with str data off,
            // if we find next \x00 pos and locate stridx by this pos, then return stridx - 1 would be the idx we want.
            //
            // new logic goto find current pos's correspond idx directly
            // stridx_map encode str_offset & str_idx by [str_offset as u64 << 32 | str_idx]
            let offset = (strdata_start + match_) as u64;
            let pos = stridx_map.partition_point(|&entry| entry >> 32 <= offset);
            let Some(idx) = pos.checked_sub(1).map(|index| stridx_map[index] as u32) else {
                continue;
            };
            if idx != last_idx {
                last_idx = idx;
                located_idx.insert(idx);
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
