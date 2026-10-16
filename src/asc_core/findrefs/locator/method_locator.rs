// Auth: MG1937

use crate::asc_core::findrefs::locator::base_locator::{_debug_log, BaseLocator};
use crate::asc_core::findrefs::locator::string_locator::StringLocator;
use crate::asc_core::findrefs::locator::type_locator::TypeLocator;
use crate::asc_core::utils::structs::{_STRUCT_HHI, _STRUCT_I};
use crate::asc_core::utils::tinydex::DEX;
use std::collections::{HashMap, HashSet};
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

pub struct MethodLocator<'a> {
    pub base: BaseLocator<'a>,
    pub parsed: bool,
    pub clz_maps: HashMap<u32, HashSet<u32>>, // {type_idx : {method_idx, ...}}
    pub method_maps: HashMap<u32, HashSet<u32>>, // {name_idx : {method_idx, ...}}
}

impl<'a> MethodLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        MethodLocator {
            base: BaseLocator::new(dex),
            parsed: false,
            clz_maps: HashMap::new(),
            method_maps: HashMap::new(),
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.base.set_debug(debug);
    }

    pub fn _debug_log(&self, stage: &str, t_start: Option<Instant>, count: Option<usize>) {
        _debug_log("MethodLocator", stage, t_start, count, self.base.debug);
    }

    // table build is very fast, dont worry about performance
    pub fn _build_map(&mut self) {
        if self.parsed {
            return;
        }
        let t_start = if self.base.debug { Some(Instant::now()) } else { None };
        let (method_ids_off, method_ids_size) = self.base.dex.header.methods;
        let mut method_ids_off = method_ids_off as usize;
        let clz_maps = &mut self.clz_maps;
        let method_maps = &mut self.method_maps;
        let buf = self.base.buf;

        for method_idx in 0..method_ids_size {
            let (class_idx, _type_idx, name_idx) = _STRUCT_HHI::unpack_from(buf, method_ids_off);
            method_ids_off += 8;
            clz_maps.entry(class_idx as u32).or_insert_with(HashSet::new).insert(method_idx);
            method_maps.entry(name_idx).or_insert_with(HashSet::new).insert(method_idx);
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
        let clz_maps = &self.clz_maps;
        for &type_idx in type_idxs {
            if let Some(mids) = clz_maps.get(&type_idx) {
                ret.extend(mids);
            }
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
            let method_maps = &self.method_maps;
            let mut ret = HashSet::new();
            for name_idx in name_idxs {
                if let Some(mids) = method_maps.get(&name_idx) {
                    ret.extend(mids);
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
            let clz_mids = self.clz_maps.get(&(type_idx as u32));
            match clz_mids {
                None => {
                    self._debug_log("locate", t_start, Some(0));
                    return HashSet::new();
                }
                Some(mids) => {
                    let clz_mids_set: HashSet<u32> = mids.iter().cloned().collect();
                    if method.is_none() {
                        self._debug_log("locate", t_start, Some(clz_mids_set.len()));
                        return clz_mids_set;
                    }
                    let ret =
                        self._match_clz_mids(&clz_mids_set, method.unwrap(), method_precise);
                    self._debug_log("locate", t_start, Some(ret.len()));
                    return ret;
                }
            }
        } else {
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
                if let Some(mids) = self.method_maps.get(&name_idx) {
                    for mid in mids {
                        if clz_mids.contains(mid) {
                            ret.insert(*mid);
                        }
                    }
                }
            }
            self._debug_log("locate", t_start, Some(ret.len()));
            return ret;
        }
    }
}
