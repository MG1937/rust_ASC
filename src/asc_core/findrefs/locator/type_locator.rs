// Auth: MG1937

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::findrefs::locator::string_locator::StringLocator;
use crate::asc_core::utils::tinydex::DEX;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

struct _STRUCT_I;
impl _STRUCT_I {
    fn unpack_from(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
    }
}

pub struct TypeLocator<'a> {
    pub base: BaseLocator<'a>,
    pub parsed: bool,
    pub type_maps: HashMap<u32, HashSet<u32>>, // {str_idx : {type_idx, ...}}
}

impl<'a> TypeLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        TypeLocator {
            base: BaseLocator::new(dex),
            parsed: false,
            type_maps: HashMap::new(),
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.base.set_debug(debug);
    }

    pub fn _debug_log(&self, stage: &str, t_start: Option<Instant>, count: Option<usize>) {
        _debug_log("TypeLocator", stage, t_start, count, self.base.debug);
    }

    pub fn _build_map(&mut self) {
        if self.parsed {
            return;
        }
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        let (type_ids_off, type_ids_size) = self.base.dex.header.types;
        let mut type_ids_off = type_ids_off as usize;
        let type_maps = &mut self.type_maps;
        let buf = self.base.buf;

        for type_idx in 0..type_ids_size {
            let str_idx = _STRUCT_I::unpack_from(buf, type_ids_off);
            type_ids_off += 4;
            type_maps.entry(str_idx).or_insert_with(HashSet::new).insert(type_idx);
        }
        self.parsed = true;
        let count = type_maps.len();
        self._debug_log("build_map", t_start, Some(count));
    }

    pub fn locate(&self, type_str: &str, str_locator: &StringLocator) -> HashSet<u32> {
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        if type_str.is_empty() {
            self._debug_log("locate", t_start, Some(0));
            return HashSet::new();
        }

        let str_idxs = str_locator.locate(type_str);
        let mut ret = HashSet::new();
        let type_maps = &self.type_maps;
        for str_idx in str_idxs {
            if let Some(types) = type_maps.get(&str_idx) {
                ret.extend(types);
            }
        }
        self._debug_log("locate", t_start, Some(ret.len()));
        ret
    }
}