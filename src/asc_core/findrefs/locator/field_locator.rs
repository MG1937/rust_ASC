// Auth: MG1937

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::findrefs::locator::string_locator::StringLocator;
use crate::asc_core::findrefs::locator::type_locator::TypeLocator;
use crate::asc_core::utils::structs::{_STRUCT_HHI, _STRUCT_I};
use crate::asc_core::utils::tinydex::DEX;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

#[derive(Clone)]
pub struct FieldFind {
    pub class: Option<(String, bool)>, // (clz, precise)
    pub field: Option<String>,
    pub field_precise: bool,
}

impl FieldFind {
    pub fn new(class: Option<(String, bool)>, field: Option<String>) -> Self {
        FieldFind {
            class,
            field,
            field_precise: false,
        }
    }

    pub fn new_exact(class: Option<(String, bool)>, field: Option<String>) -> Self {
        FieldFind {
            class,
            field,
            field_precise: true,
        }
    }
}

pub struct FieldLocator<'a> {
    pub base: BaseLocator<'a>,
    pub parsed: bool,
    pub clz_maps: HashMap<u32, HashSet<u32>>, // {type_idx : {field_idx, ...}}
    pub field_maps: HashMap<u32, HashSet<u32>>, // {name_idx : {field_idx, ...}}
}

impl<'a> FieldLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        FieldLocator {
            base: BaseLocator::new(dex),
            parsed: false,
            clz_maps: HashMap::new(),
            field_maps: HashMap::new(),
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.base.set_debug(debug);
    }

    pub fn _debug_log(&self, stage: &str, t_start: Option<Instant>, count: Option<usize>) {
        _debug_log("FieldLocator", stage, t_start, count, self.base.debug);
    }

    // table build is very fast, dont worry about performance
    pub fn _build_map(&mut self) {
        if self.parsed {
            return;
        }
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        let (field_ids_off, field_ids_size) = self.base.dex.header.fields;
        let mut field_ids_off = field_ids_off as usize;
        let clz_maps = &mut self.clz_maps;
        let field_maps = &mut self.field_maps;
        let buf = self.base.buf;

        for field_idx in 0..field_ids_size {
            let (class_idx, _type_idx, name_idx) = _STRUCT_HHI::unpack_from(buf, field_ids_off);
            field_ids_off += 8;
            clz_maps.entry(class_idx as u32).or_insert_with(HashSet::new).insert(field_idx);
            field_maps.entry(name_idx).or_insert_with(HashSet::new).insert(field_idx);
        }
        self.parsed = true;
        self._debug_log("build_map", t_start, Some(field_ids_size as usize));
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

    pub fn _collect_clz_fids(&self, type_idxs: &HashSet<u32>) -> HashSet<u32> {
        let mut ret = HashSet::new();
        let clz_maps = &self.clz_maps;
        for &type_idx in type_idxs {
            if let Some(fids) = clz_maps.get(&type_idx) {
                ret.extend(fids);
            }
        }
        ret
    }

    pub fn _match_clz_fids(
        &self,
        clz_fids: &HashSet<u32>,
        field: &str,
        precise: bool,
    ) -> HashSet<u32> {
        let mut ret = HashSet::new();
        for &fid in clz_fids {
            let f = self.base.dex.get_field(fid);
            let name = f.name();
            if if precise {
                name == field
            } else {
                name.contains(field)
            } {
                ret.insert(fid);
            }
        }
        ret
    }

    /// Locate a one-shot field query without materializing two maps of sets.
    /// Each field row already stores its owner and name indices; selecting rows
    /// after resolving the query is cheaper than indexing every field first.
    /// The indexed `locate` API remains available for callers reusing a locator.
    pub fn locate_unindexed(
        &self,
        find: &FieldFind,
        str_locator: &StringLocator,
        type_locator: &TypeLocator,
    ) -> HashSet<u32> {
        let class = find.class.as_ref().filter(|(name, _)| !name.is_empty());
        let field = find.field.as_deref().filter(|name| !name.is_empty());
        if class.is_none() && field.is_none() {
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
        let name_indices = field
            .filter(|_| !find.field_precise && !precise_class)
            .map(|name| str_locator.locate(name));
        if name_indices.as_ref().is_some_and(HashSet::is_empty) {
            return HashSet::new();
        }

        let (offset, count) = self.base.dex.header.fields;
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
            } else if let Some(wanted) = field {
                let member = self.base.dex.get_field(index);
                let name = member.name();
                let matches = if find.field_precise {
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

    // find struct: {"class" : ["None|clz", precise], "field" : "None|fuzzy_field"}
    // the two values cannot both be None
    // if class not None, input clz must be precise dalvik format value or fuzzy clz
    // if field not None, input field name can be a fuzzy value
    // if class is None, find out all field idx that contains the fuzzy field name while dont give shit about class
    // if class is set, find out all fields below this class which matches the field condition
    pub fn locate(&self, find: &FieldFind, str_locator: &StringLocator, type_locator: &TypeLocator) -> HashSet<u32> {
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };

        let mut clz = find.class.as_ref();
        let field = find.field.as_ref();
        let field_precise = find.field_precise;
        let mut clz_precise = true;
        if let Some((clz_str, precise)) = clz {
            if clz_str.is_empty() {
                clz = None;
            } else {
                clz_precise = *precise;
            }
        }
        let field = if field.map_or(false, |s| s.is_empty()) { None } else { field };
        if clz.is_none() && field.is_none() {
            self._debug_log("locate", t_start, Some(0));
            return HashSet::new();
        }

        if clz.is_none() {
            if field_precise {
                let mut ret = HashSet::new();
                for field_idx in 0..self.base.dex.header.fields.1 {
                    if self.base.dex.get_field(field_idx).name() == field.unwrap().as_str() {
                        ret.insert(field_idx);
                    }
                }
                return ret;
            }
            let name_idxs = str_locator.locate(field.unwrap());
            let field_maps = &self.field_maps;
            let mut ret = HashSet::new();
            for name_idx in name_idxs {
                if let Some(fids) = field_maps.get(&name_idx) {
                    ret.extend(fids);
                }
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
            let clz_fids = self.clz_maps.get(&(type_idx as u32));
            match clz_fids {
                None => {
                    self._debug_log("locate", t_start, Some(0));
                    return HashSet::new();
                }
                Some(fids) => {
                    let clz_fids_set: HashSet<u32> = fids.iter().cloned().collect();
                    if field.is_none() {
                        self._debug_log("locate", t_start, Some(clz_fids_set.len()));
                        return clz_fids_set;
                    }
                    let ret =
                        self._match_clz_fids(&clz_fids_set, field.unwrap(), field_precise);
                    self._debug_log("locate", t_start, Some(ret.len()));
                    return ret;
                }
            }
        } else {
            let clz_fids = self._collect_clz_fids(&type_locator.locate(clz_str, str_locator));
            if clz_fids.is_empty() {
                self._debug_log("locate", t_start, Some(0));
                return HashSet::new();
            }
            if field.is_none() {
                self._debug_log("locate", t_start, Some(clz_fids.len()));
                return clz_fids;
            }
            if field_precise {
                return self._match_clz_fids(&clz_fids, field.unwrap(), true);
            }
            // fuzzy class + fuzzy field
            let name_idxs = str_locator.locate(field.unwrap());
            let mut ret = HashSet::new();
            for name_idx in name_idxs {
                if let Some(fids) = self.field_maps.get(&name_idx) {
                    for fid in fids {
                        if clz_fids.contains(fid) {
                            ret.insert(*fid);
                        }
                    }
                }
            }
            self._debug_log("locate", t_start, Some(ret.len()));
            return ret;
        }
    }
}
