// Auth: MG1937

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::findrefs::locator::string_locator::StringLocator;
use crate::asc_core::findrefs::locator::type_locator::TypeLocator;
use crate::asc_core::utils::structs::{_STRUCT_HHI, _STRUCT_I};
use crate::asc_core::utils::tinydex::DEX;
use std::collections::HashSet;
use std::time::Instant;

#[derive(Clone)]
pub struct MethodFind {
    pub class: Option<(String, bool)>, // (clz, precise)
    pub method: Option<String>,
    pub method_precise: bool,
}

impl MethodFind {
    pub fn new(class: Option<(String, bool)>, method: Option<String>) -> Self {
        MethodFind {
            class,
            method,
            method_precise: false,
        }
    }

    pub fn new_exact(class: Option<(String, bool)>, method: Option<String>) -> Self {
        MethodFind {
            class,
            method,
            method_precise: true,
        }
    }
}

/// Groups `method_id_item` rows two ways (by owning class, by name string) using
/// CSR arrays instead of `HashMap<u32, HashSet<u32>>`. A large DEX holds
/// hundreds of thousands of methods spread over tens of thousands of distinct
/// names, so the map-of-sets variant allocated one hash set per name and paid a
/// hash per insert. Counting sort is two linear passes over the method table.
pub struct MethodLocator<'a> {
    pub base: BaseLocator<'a>,
    pub parsed: bool,
    clz_offsets: Vec<u32>, // len = type_ids_size + 1
    clz_mids: Vec<u32>,    // method idxs grouped by class_idx
    name_offsets: Vec<u32>, // len = string_ids_size + 1
    name_mids: Vec<u32>,   // method idxs grouped by name_idx
}

impl<'a> MethodLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        MethodLocator {
            base: BaseLocator::new(dex),
            parsed: false,
            clz_offsets: Vec::new(),
            clz_mids: Vec::new(),
            name_offsets: Vec::new(),
            name_mids: Vec::new(),
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.base.set_debug(debug);
    }

    pub fn _debug_log(&self, stage: &str, t_start: Option<Instant>, count: Option<usize>) {
        _debug_log("MethodLocator", stage, t_start, count, self.base.debug);
    }

    fn clz_slice(&self, class_idx: u32) -> &[u32] {
        let index = class_idx as usize;
        match (self.clz_offsets.get(index), self.clz_offsets.get(index + 1)) {
            (Some(&start), Some(&end)) => &self.clz_mids[start as usize..end as usize],
            _ => &[],
        }
    }

    fn name_slice(&self, name_idx: u32) -> &[u32] {
        let index = name_idx as usize;
        match (self.name_offsets.get(index), self.name_offsets.get(index + 1)) {
            (Some(&start), Some(&end)) => &self.name_mids[start as usize..end as usize],
            _ => &[],
        }
    }

    pub fn _build_map(&mut self) {
        if self.parsed {
            return;
        }
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        let (method_ids_off, method_ids_size) = self.base.dex.header.methods;
        let (_, type_ids_size) = self.base.dex.header.types;
        let (_, string_ids_size) = self.base.dex.header.strings;
        let buf = self.base.buf;
        let mut method_ids_off = method_ids_off as usize;

        self.clz_offsets = vec![0u32; type_ids_size as usize + 1];
        self.name_offsets = vec![0u32; string_ids_size as usize + 1];

        // Bounded counters: malformed indices fall outside the table and are
        // dropped rather than trusted, matching the previous map behaviour.
        for _ in 0..method_ids_size {
            let (class_idx, _proto_idx, name_idx) = _STRUCT_HHI::unpack_from(buf, method_ids_off);
            method_ids_off += 8;
            if let Some(slot) = self.clz_offsets.get_mut(class_idx as usize + 1) {
                *slot += 1;
            }
            if let Some(slot) = self.name_offsets.get_mut(name_idx as usize + 1) {
                *slot += 1;
            }
        }
        for index in 1..self.clz_offsets.len() {
            self.clz_offsets[index] += self.clz_offsets[index - 1];
        }
        for index in 1..self.name_offsets.len() {
            self.name_offsets[index] += self.name_offsets[index - 1];
        }
        self.clz_mids = vec![0u32; self.clz_offsets.last().copied().unwrap_or(0) as usize];
        self.name_mids = vec![0u32; self.name_offsets.last().copied().unwrap_or(0) as usize];

        let mut clz_cursor = self.clz_offsets.clone();
        let mut name_cursor = self.name_offsets.clone();
        let mut method_ids_off = self.base.dex.header.methods.0 as usize;
        for method_idx in 0..method_ids_size {
            let (class_idx, _proto_idx, name_idx) = _STRUCT_HHI::unpack_from(buf, method_ids_off);
            method_ids_off += 8;
            let clz_index = class_idx as usize;
            if let Some(cursor) = clz_cursor.get_mut(clz_index) {
                self.clz_mids[*cursor as usize] = method_idx;
                *cursor += 1;
            }
            let name_index = name_idx as usize;
            if let Some(cursor) = name_cursor.get_mut(name_index) {
                self.name_mids[*cursor as usize] = method_idx;
                *cursor += 1;
            }
        }
        self.parsed = true;
        self._debug_log("build_map", t_start, Some(method_ids_size as usize));
    }

    // which is different with type locator, this func for precise clz name
    // while type locator is for fuzzy search
    pub fn _find_type_idx_precisely(&self, clz: &str) -> i32 {
        let mut left: i32 = 0;
        let (type_ids_off, type_ids_size) = self.base.dex.header.types;
        let mut right = type_ids_size as i32 - 1;
        let buf = self.base.buf;

        while left <= right {
            let mid = (left + right) >> 1;
            let desc_idx = _STRUCT_I::unpack_from(buf, (type_ids_off as usize) + ((mid as usize) << 2)) as usize;
            let desc = &self.base.dex.get_string(desc_idx).value;
            if desc == clz {
                return mid;
            }
            if desc.as_str() < clz {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }
        -1
    }

    pub fn _collect_clz_mids(&self, type_idxs: &HashSet<u32>) -> HashSet<u32> {
        let mut ret = HashSet::new();
        for &type_idx in type_idxs {
            ret.extend(self.clz_slice(type_idx));
        }
        ret
    }

    pub fn _match_clz_mids(
        &self,
        clz_mids: &HashSet<u32>,
        method: &str,
        precise: bool,
    ) -> HashSet<u32> {
        let mut ret = HashSet::new();
        for &mid in clz_mids {
            let m = self.base.dex.get_method(mid);
            let name = m.name();
            if if precise {
                name == method
            } else {
                name.contains(method)
            } {
                ret.insert(mid);
            }
        }
        ret
    }

    /// Locate a one-shot method query without materializing two maps of sets.
    /// Each method row already stores its owner and name indices; selecting rows
    /// after resolving the query is cheaper than indexing every method first.
    /// The indexed `locate` API remains available for callers reusing a locator.
    pub fn locate_unindexed(
        &self,
        find: &MethodFind,
        str_locator: &StringLocator,
        type_locator: &TypeLocator,
    ) -> HashSet<u32> {
        let class = find.class.as_ref().filter(|(name, _)| !name.is_empty());
        let method = find.method.as_deref().filter(|name| !name.is_empty());
        if class.is_none() && method.is_none() {
            return HashSet::new();
        }

        let precise_class = class.is_some_and(|(_, precise)| *precise);
        let class_indices = class.map(|(name, precise)| {
            if *precise {
                let index = self._find_type_idx_precisely(name);
                if index < 0 {
                    HashSet::new()
                } else {
                    HashSet::from([index as u32])
                }
            } else {
                type_locator.locate(name, str_locator)
            }
        });
        if class_indices.as_ref().is_some_and(HashSet::is_empty) {
            return HashSet::new();
        }

        // Preserve both established match paths: exact-class queries compare
        // decoded member names; unscoped/fuzzy-class substring queries resolve
        // matching string indices through StringLocator first.
        let name_indices = method
            .filter(|_| !find.method_precise && !precise_class)
            .map(|name| str_locator.locate(name));
        if name_indices.as_ref().is_some_and(HashSet::is_empty) {
            return HashSet::new();
        }

        let (offset, count) = self.base.dex.header.methods;
        let mut found = HashSet::new();
        for index in 0..count {
            let (owner, _, name_index) =
                _STRUCT_HHI::unpack_from(self.base.buf, offset as usize + index as usize * 8);
            if class_indices
                .as_ref()
                .is_some_and(|classes| !classes.contains(&(owner as u32)))
            {
                continue;
            }
            if let Some(names) = &name_indices {
                if !names.contains(&name_index) {
                    continue;
                }
            } else if let Some(wanted) = method {
                let member = self.base.dex.get_method(index);
                let name = member.name();
                let matches = if find.method_precise {
                    name == wanted
                } else {
                    name.contains(wanted)
                };
                if !matches {
                    continue;
                }
            }
            found.insert(index);
        }
        found
    }

    // find struct: {"class" : ["None|clz", precise], "method" : "None|fuzzy_method"}
    // the two values cannot both be None
    // if class not None, input clz must be precise dalvik format value or fuzzy clz
    // if method not None, input method name can be a fuzzy value
    // if class is None, find out all method idx that contains the fuzzy method name while dont give shit about class
    // if class is set, find out all methods below this class which matches the method condition
    pub fn locate(&self, find: &MethodFind, str_locator: &StringLocator, type_locator: &TypeLocator) -> HashSet<u32> {
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };

        let mut clz = find.class.as_ref();
        let method = find.method.as_ref();
        let method_precise = find.method_precise;
        let mut clz_precise = true;
        if let Some((clz_str, precise)) = clz {
            if clz_str.is_empty() {
                clz = None;
            } else {
                clz_precise = *precise;
            }
        }
        let method = if method.map_or(false, |s| s.is_empty()) { None } else { method };
        if clz.is_none() && method.is_none() {
            self._debug_log("locate", t_start, Some(0));
            return HashSet::new();
        }

        if clz.is_none() {
            if method_precise {
                let mut ret = HashSet::new();
                for method_idx in 0..self.base.dex.header.methods.1 {
                    if self.base.dex.get_method(method_idx).name() == method.unwrap().as_str() {
                        ret.insert(method_idx);
                    }
                }
                return ret;
            }
            let name_idxs = str_locator.locate(method.unwrap());
            let mut ret = HashSet::new();
            for name_idx in name_idxs {
                ret.extend(self.name_slice(name_idx));
            }
            self._debug_log("locate", t_start, Some(ret.len()));
            return ret;
        }

        let (clz_str, _) = clz.unwrap();
        if clz_precise {
            let type_idx = self._find_type_idx_precisely(clz_str);
            if type_idx == -1 {
                self._debug_log("locate", t_start, Some(0));
                return HashSet::new();
            }
            let clz_mids: HashSet<u32> = self.clz_slice(type_idx as u32).iter().copied().collect();
            if clz_mids.is_empty() {
                self._debug_log("locate", t_start, Some(0));
                return HashSet::new();
            }
            if method.is_none() {
                self._debug_log("locate", t_start, Some(clz_mids.len()));
                return clz_mids;
            }
            let ret = self._match_clz_mids(&clz_mids, method.unwrap(), method_precise);
            self._debug_log("locate", t_start, Some(ret.len()));
            return ret;
        }
        let clz_mids = self._collect_clz_mids(&type_locator.locate(clz_str, str_locator));
        if clz_mids.is_empty() {
            self._debug_log("locate", t_start, Some(0));
            return HashSet::new();
        }
        if method.is_none() {
            self._debug_log("locate", t_start, Some(clz_mids.len()));
            return clz_mids;
        }
        if method_precise {
            return self._match_clz_mids(&clz_mids, method.unwrap(), true);
        }
        // fuzzy class + fuzzy method
        let name_idxs = str_locator.locate(method.unwrap());
        let mut ret = HashSet::new();
        for name_idx in name_idxs {
            for mid in self.name_slice(name_idx) {
                if clz_mids.contains(mid) {
                    ret.insert(*mid);
                }
            }
        }
        self._debug_log("locate", t_start, Some(ret.len()));
        ret
    }
}
