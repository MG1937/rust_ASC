// Auth: MG1937

use crate::asc_core::findrefs::locator::field_locator::{FieldFind, FieldLocator};
use crate::asc_core::findrefs::locator::insn_locator::InsnLocator;
use crate::asc_core::findrefs::locator::method_locator::{MethodFind, MethodLocator};
use crate::asc_core::findrefs::locator::string_locator::StringLocator;
use crate::asc_core::findrefs::locator::type_locator::TypeLocator;
use crate::asc_core::findrefs::scan::class_def_item_scan::ClassDefItemScanner;
use crate::asc_core::findrefs::scan::code_item_scan::CodeItemScanner;
use crate::asc_core::utils::tinydex::DEX;
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub struct FindRefInput {
    pub string: Option<String>,
    pub type_: Option<String>,
    pub method: Option<MethodFind>,
    pub field: Option<FieldFind>,
    pub extends: Option<String>,
    pub impl_: Option<String>,
}

impl FindRefInput {
    pub fn new(
        string: Option<String>,
        type_: Option<String>,
        method: Option<MethodFind>,
        field: Option<FieldFind>,
    ) -> Self {
        FindRefInput {
            string,
            type_,
            method,
            field,
            extends: None,
            impl_: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.string.is_none()
            && self.type_.is_none()
            && self.method.is_none()
            && self.field.is_none()
            && self.extends.is_none()
            && self.impl_.is_none()
    }
}

pub struct FindRefOutput {
    pub string: Vec<Option<Vec<u32>>>,
    pub type_: Vec<Option<Vec<u32>>>,
    pub method: Vec<Option<Vec<u32>>>,
    pub field: Vec<Option<Vec<u32>>>,
    pub mark_idx: Vec<u32>,
}

/// Unified result of a reference query.
///
/// `extends`/`impl` are class-definition lookups that short-circuit the opcode
/// scan, so they cannot be expressed as containing-method indexes.
pub enum FindRefResult {
    /// `extends`/`impl`: class def indexes (a class's `class_idx` type index).
    ClassDefs(Vec<u32>),
    /// string/type/method/field: located indexes plus containing methods.
    Refs(FindRefOutput),
}

pub struct FindRefManager<'a> {
    pub dex: &'a DEX,
    pub debug: bool,
    pub str_locator: Option<StringLocator<'a>>,
    pub type_locator: Option<TypeLocator<'a>>,
    pub method_locator: Option<MethodLocator<'a>>,
    pub field_locator: Option<FieldLocator<'a>>,
    pub insn_locator: Option<InsnLocator<'a>>,
}

impl<'a> FindRefManager<'a> {
    pub fn new(dex: &'a DEX, debug: bool) -> Self {
        FindRefManager {
            dex,
            debug,
            str_locator: None,
            type_locator: None,
            method_locator: None,
            field_locator: None,
            insn_locator: None,
        }
    }

    pub fn _get_str_locator(&mut self, build: bool) -> &mut StringLocator<'a> {
        if self.str_locator.is_none() {
            let mut locator = StringLocator::new(self.dex);
            locator.set_debug(self.debug);
            self.str_locator = Some(locator);
        }
        if build {
            let locator = self.str_locator.as_mut().unwrap();
            if !locator.parsed {
                locator._build_map();
            }
        }
        self.str_locator.as_mut().unwrap()
    }

    pub fn _get_type_locator(&mut self, build: bool) -> &mut TypeLocator<'a> {
        if self.type_locator.is_none() {
            let mut locator = TypeLocator::new(self.dex);
            locator.set_debug(self.debug);
            self.type_locator = Some(locator);
        }
        if build {
            let locator = self.type_locator.as_mut().unwrap();
            if !locator.parsed {
                locator._build_map();
            }
        }
        self.type_locator.as_mut().unwrap()
    }

    pub fn _get_method_locator(&mut self, build: bool) -> &mut MethodLocator<'a> {
        if self.method_locator.is_none() {
            let mut locator = MethodLocator::new(self.dex);
            locator.set_debug(self.debug);
            self.method_locator = Some(locator);
        }
        if build {
            let locator = self.method_locator.as_mut().unwrap();
            if !locator.parsed {
                locator._build_map();
            }
        }
        self.method_locator.as_mut().unwrap()
    }

    pub fn _get_field_locator(&mut self, build: bool) -> &mut FieldLocator<'a> {
        if self.field_locator.is_none() {
            let mut locator = FieldLocator::new(self.dex);
            locator.set_debug(self.debug);
            self.field_locator = Some(locator);
        }
        if build {
            let locator = self.field_locator.as_mut().unwrap();
            if !locator.parsed {
                locator._build_map();
            }
        }
        self.field_locator.as_mut().unwrap()
    }

    fn _ensure_insn_locator(&mut self) -> &mut InsnLocator<'a> {
        if self.insn_locator.is_none() {
            let mut locator = InsnLocator::new(self.dex);
            locator.set_debug(self.debug);
            self.insn_locator = Some(locator);
        }
        let locator = self.insn_locator.as_mut().unwrap();
        if !locator.parsed {
            locator.parse();
        }
        self.insn_locator.as_mut().unwrap()
    }

    /// Locate classes whose superclass is the target class.
    fn scan_extends(&mut self, target_clz: &str) -> Vec<u32> {
        let type_locator = self._get_type_locator(false);
        ClassDefItemScanner::new(type_locator).scan_extends(target_clz)
    }

    /// Locate classes that implement the target interface.
    fn scan_implements(&mut self, target_clz: &str) -> Vec<u32> {
        let type_locator = self._get_type_locator(false);
        ClassDefItemScanner::new(type_locator).scan_implements(target_clz)
    }

    /// Single entry point for every findrefs query.
    ///
    /// `extends`/`impl` are handled here and returned as
    /// [`FindRefResult::ClassDefs`]; they short-circuit the opcode scan. All
    /// other keys locate their indexes, write them back through the code-item
    /// scanner and return [`FindRefResult::Refs`].
    ///
    /// Callers must not reach for the class-def scanner directly: keeping the
    /// dispatch here is what keeps `extends`/`impl` and opcode queries on one
    /// contract.
    pub fn find_ref(&mut self, find: &FindRefInput, mark: bool) -> Option<FindRefResult> {
        if let Some(target) = find.extends.as_deref() {
            return Some(FindRefResult::ClassDefs(self.scan_extends(target)));
        }
        if let Some(target) = find.impl_.as_deref() {
            return Some(FindRefResult::ClassDefs(self.scan_implements(target)));
        }

        let mut has_idx = false;

        let profile = std::env::var_os("RASC_PROFILE").is_some();
        let ph0 = profile.then(std::time::Instant::now);
        // Phase 0: build all required locators first (drop mutable refs before Phase 1)
        if find.string.is_some() || find.type_.is_some() || find.method.is_some() || find.field.is_some() {
            let _ = self._get_str_locator(true);
        }
        if find.type_.is_some() || find.method.is_some() || find.field.is_some() {
            // Only type queries or fuzzy declaring-class filters use the type
            // adjacency map. Exact/unscoped member queries read the id tables.
            let fuzzy_method_class = find.method.as_ref().is_some_and(|query| {
                query.class.as_ref().is_some_and(|(name, precise)| !precise && !name.is_empty())
            });
            let fuzzy_field_class = find.field.as_ref().is_some_and(|query| {
                query.class.as_ref().is_some_and(|(name, precise)| !precise && !name.is_empty())
            });
            let _ = self._get_type_locator(
                find.type_.is_some() || fuzzy_method_class || fuzzy_field_class,
            );
        }
        if find.method.is_some() {
            let _ = self._get_method_locator(false);
        }
        if find.field.is_some() {
            // A find_ref call is a one-shot query over this DEX. Resolve its
            // indices directly instead of building maps for every field.
            let _ = self._get_field_locator(false);
        }

        let ph1 = profile.then(std::time::Instant::now);
        // Phase 1: locate all indices (immutable borrows only)
        let string_result: Option<HashSet<u32>>;
        let type_result: Option<HashSet<u32>>;
        let method_result: Option<HashSet<u32>>;
        let field_result: Option<HashSet<u32>>;

        if let Some(ref s) = find.string {
            let r = self.str_locator.as_ref().unwrap().locate(s);
            if !r.is_empty() { has_idx = true; }
            string_result = Some(r);
        } else { string_result = None; }

        if let Some(ref t) = find.type_ {
            let str_loc = self.str_locator.as_ref().unwrap();
            let type_loc = self.type_locator.as_ref().unwrap();
            let r = type_loc.locate(t, str_loc);
            if !r.is_empty() { has_idx = true; }
            type_result = Some(r);
        } else { type_result = None; }

        if let Some(ref m) = find.method {
            let str_loc = self.str_locator.as_ref().unwrap();
            let type_loc = self.type_locator.as_ref().unwrap();
            let method_loc = self.method_locator.as_ref().unwrap();
            let r = method_loc.locate_unindexed(m, str_loc, type_loc);
            if !r.is_empty() { has_idx = true; }
            method_result = Some(r);
        } else { method_result = None; }

        if let Some(ref f) = find.field {
            let str_loc = self.str_locator.as_ref().unwrap();
            let type_loc = self.type_locator.as_ref().unwrap();
            let field_loc = self.field_locator.as_ref().unwrap();
            let r = field_loc.locate_unindexed(f, str_loc, type_loc);
            if !r.is_empty() { has_idx = true; }
            field_result = Some(r);
        } else { field_result = None; }

        let ph2 = profile.then(std::time::Instant::now);
        if profile {
            eprintln!(
                "[PROF] build_locators={:.3}ms locate_idxs={:.3}ms",
                (ph1.unwrap() - ph0.unwrap()).as_secs_f64() * 1e3,
                (ph2.unwrap() - ph1.unwrap()).as_secs_f64() * 1e3
            );
        }
        if find.is_empty() {
            return None;
        }
        if !has_idx {
            return Some(FindRefResult::Refs(FindRefOutput {
                string: string_result.map(|_| Vec::new()).unwrap_or_default(),
                type_: type_result.map(|_| Vec::new()).unwrap_or_default(),
                method: method_result.map(|_| Vec::new()).unwrap_or_default(),
                field: field_result.map(|_| Vec::new()).unwrap_or_default(),
                mark_idx: Vec::new(),
            }));
        }

        // Phase 2: build scan map and run scanner
        let tp0 = profile.then(std::time::Instant::now);
        let insn_locator = self._ensure_insn_locator();
        let tp1 = profile.then(std::time::Instant::now);
        let mut scanner = CodeItemScanner::new(insn_locator);

        let mut scan_map: HashMap<String, Vec<Option<Vec<u32>>>> = HashMap::new();
        if let Some(r) = string_result {
            let v: Vec<Option<Vec<u32>>> = r.into_iter().map(|x| Some(vec![x])).collect();
            scan_map.insert("string".to_string(), v);
        }
        if let Some(r) = type_result {
            let v: Vec<Option<Vec<u32>>> = r.into_iter().map(|x| Some(vec![x])).collect();
            scan_map.insert("type".to_string(), v);
        }
        if let Some(r) = method_result {
            let v: Vec<Option<Vec<u32>>> = r.into_iter().map(|x| Some(vec![x])).collect();
            scan_map.insert("method".to_string(), v);
        }
        if let Some(r) = field_result {
            let v: Vec<Option<Vec<u32>>> = r.into_iter().map(|x| Some(vec![x])).collect();
            scan_map.insert("field".to_string(), v);
        }

        scanner.scan(&mut scan_map, mark, insn_locator);
        let tp2 = profile.then(std::time::Instant::now);
        if profile {
            eprintln!(
                "[PROF] insn_parse={:.3}ms scan={:.3}ms",
                (tp1.unwrap() - tp0.unwrap()).as_secs_f64() * 1e3,
                (tp2.unwrap() - tp1.unwrap()).as_secs_f64() * 1e3
            );
        }
        let mark_idx = std::mem::take(&mut scanner.mark_idx);

        let get_or_default = |key: &str| -> Vec<Option<Vec<u32>>> {
            scan_map.get(key).cloned().unwrap_or_default()
        };

        Some(FindRefResult::Refs(FindRefOutput {
            string: get_or_default("string"),
            type_: get_or_default("type"),
            method: get_or_default("method"),
            field: get_or_default("field"),
            mark_idx,
        }))
    }
}