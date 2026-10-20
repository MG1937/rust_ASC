// Auth: MG1937

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::findrefs::locator::string_locator::StringLocator;
use crate::asc_core::utils::structs::_STRUCT_I;
use crate::asc_core::utils::tinydex::DEX;
use std::collections::HashSet;
use std::time::Instant;

/// Maps string index -> type idxs holding that descriptor using CSR arrays.
/// `type_ids` is already ordered by string index in a valid DEX, so a single
/// counting pass replaces one hash set per distinct descriptor.
pub struct TypeLocator<'a> {
    pub base: BaseLocator<'a>,
    pub parsed: bool,
    str_offsets: Vec<u32>, // len = string_ids_size + 1
    type_idxs: Vec<u32>,   // type idxs grouped by descriptor string index
}

impl<'a> TypeLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        TypeLocator {
            base: BaseLocator::new(dex),
            parsed: false,
            str_offsets: Vec::new(),
            type_idxs: Vec::new(),
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.base.set_debug(debug);
    }

    pub fn _debug_log(&self, stage: &str, t_start: Option<Instant>, count: Option<usize>) {
        _debug_log("TypeLocator", stage, t_start, count, self.base.debug);
    }

    fn types_of(&self, str_idx: u32) -> &[u32] {
        let index = str_idx as usize;
        match (self.str_offsets.get(index), self.str_offsets.get(index + 1)) {
            (Some(&start), Some(&end)) => &self.type_idxs[start as usize..end as usize],
            _ => &[],
        }
    }

    pub fn _build_map(&mut self) {
        if self.parsed {
            return;
        }
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        let (type_ids_off, type_ids_size) = self.base.dex.header.types;
        let (_, string_ids_size) = self.base.dex.header.strings;
        let buf = self.base.buf;
        let mut type_ids_off = type_ids_off as usize;

        self.str_offsets = vec![0u32; string_ids_size as usize + 1];
        self.type_idxs = Vec::new();

        for _ in 0..type_ids_size {
            let str_idx = _STRUCT_I::unpack_from(buf, type_ids_off);
            type_ids_off += 4;
            if let Some(slot) = self.str_offsets.get_mut(str_idx as usize + 1) {
                *slot += 1;
            }
        }
        for index in 1..self.str_offsets.len() {
            self.str_offsets[index] += self.str_offsets[index - 1];
        }
        self.type_idxs = vec![0u32; self.str_offsets.last().copied().unwrap_or(0) as usize];

        let mut cursor = self.str_offsets.clone();
        let mut type_ids_off = self.base.dex.header.types.0 as usize;
        for type_idx in 0..type_ids_size {
            let str_idx = _STRUCT_I::unpack_from(buf, type_ids_off);
            type_ids_off += 4;
            if let Some(slot) = cursor.get_mut(str_idx as usize) {
                self.type_idxs[*slot as usize] = type_idx;
                *slot += 1;
            }
        }
        self.parsed = true;
        self._debug_log("build_map", t_start, Some(type_ids_size as usize));
    }

    pub fn locate(&self, type_str: &str, str_locator: &StringLocator) -> HashSet<u32> {
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        if type_str.is_empty() {
            self._debug_log("locate", t_start, Some(0));
            return HashSet::new();
        }

        let str_idxs = str_locator.locate(type_str);
        let mut ret = HashSet::new();
        for str_idx in str_idxs {
            ret.extend(self.types_of(str_idx));
        }
        self._debug_log("locate", t_start, Some(ret.len()));
        ret
    }
}
