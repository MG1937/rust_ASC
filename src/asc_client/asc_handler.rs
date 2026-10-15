// Auth: MG1937
// Strict 1:1 translation from Python asc_handler.py

use std::collections::{HashMap, HashSet};
use std::vec;

use crate::asc_core::core::dex::dex_manager::DexManager;
use crate::asc_core::findrefs::findrefs_manager::{FindRefInput, FindRefManager};
use crate::asc_core::findrefs::locator::field_locator::FieldFind;
use crate::asc_core::findrefs::locator::method_locator::MethodFind;
use crate::asc_core::utils::decompiler::{
    decompile_dex_bytes, decompile_dex_bytes_with_metadata, MemberReference,
};
use crate::asc_core::utils::tinydex::DEX;

// -----------------------------------------------------------------

/// Core orchestrator integrating DexManager, FindRefManager and decompiler
pub struct AscHandler {
    pub debug: bool,
}

impl AscHandler {
    pub fn new(debug: bool) -> Self {
        AscHandler { debug }
    }

    /// Extract and decompile the specified class.
    pub fn getclass(&self, dex_buf: &[u8], dalvik_class: &str) -> String {
        let mut manager = DexManager::from_bytes(dex_buf.to_vec(), self.debug);
        let new_dex_bytes = manager.extract_and_rebuild(dalvik_class);
        decompile_dex_bytes(&new_dex_bytes, dalvik_class)
    }

    pub fn getclass_with_metadata(
        &self,
        dex_buf: &[u8],
        dalvik_class: &str,
    ) -> (String, Vec<MemberReference>) {
        let mut manager = DexManager::from_bytes(dex_buf.to_vec(), self.debug);
        let new_dex_bytes = manager.extract_and_rebuild(dalvik_class);
        decompile_dex_bytes_with_metadata(&new_dex_bytes, dalvik_class)
    }

    fn _format_method(&self, dex: &DEX, midx: usize) -> String {
        let method = dex.get_method(midx as u32);
        format!("{}->{}", method.cls().fullname, method.name())
    }

    fn _format_matched_name(&self, dex: &DEX, find_type: &str, idx: usize) -> String {
        match find_type {
            "string" => dex.get_string(idx).value.clone(),
            "type" => dex.get_type(idx as u32).descriptor.clone(),
            "method" => {
                let method = dex.get_method(idx as u32);
                format!("{}->{}", method.cls().fullname, method.name())
            }
            _ => {
                // field
                let field = dex.get_field(idx as u32);
                format!("{}->{}", field.cls().fullname, field.name())
            }
        }
    }

    /// Find references and return formatted result lines
    pub fn findrefs(
        &self,
        dex_name: &str,
        dex_buf: &[u8],
        find_type: &str,
        find: &FindRefInput,
        aggregate: bool,
    ) -> Vec<String> {
        let dex = DEX::parse(dex_buf, dex_name);
        self._findrefs(dex_name, &dex, find_type, find, aggregate)
    }

    pub fn findrefs_vec(
        &self,
        dex_name: &str,
        dex_buf: Vec<u8>,
        find_type: &str,
        find: &FindRefInput,
        aggregate: bool,
    ) -> Vec<String> {
        let dex = DEX::from_vec(dex_buf, dex_name);
        self._findrefs(dex_name, &dex, find_type, find, aggregate)
    }

    fn _findrefs(
        &self,
        dex_name: &str,
        dex: &DEX,
        find_type: &str,
        find: &FindRefInput,
        aggregate: bool,
    ) -> Vec<String> {
        let mut ref_manager = FindRefManager::new(dex, self.debug);
        let output = ref_manager.find_ref(find, true);

        let Some(out) = output else {
            return Vec::new();
        };

        let matched_idxs: Vec<usize> = out.mark_idx.iter().map(|&x| x as usize).collect();

        let mids: &Vec<Option<Vec<u32>>> = match find_type {
            "string" => &out.string,
            "type" => &out.type_,
            "method" => &out.method,
            "field" => &out.field,
            _ => return Vec::new(),
        };

        if matched_idxs.is_empty() {
            return Vec::new();
        }

        if !aggregate {
            let mut ret = Vec::new();
            for (i, mid_entry) in mids.iter().enumerate() {
                let idx = matched_idxs.get(i).copied().unwrap_or(0);
                let matched = self._format_matched_name(&dex, find_type, idx);
                let Some(mid_list) = mid_entry else { continue; };
                for &mid in mid_list {
                    ret.push(format!(
                        "{} | {} | matched=({})",
                        dex_name,
                        self._format_method(&dex, mid as usize),
                        matched
                    ));
                }
            }
            return ret;
        }

        // aggregate = true
        let mut grouped: HashMap<usize, HashSet<usize>> = HashMap::new();
        for (i, mid_entry) in mids.iter().enumerate() {
            let idx = matched_idxs.get(i).copied().unwrap_or(0);
            let Some(mid_list) = mid_entry else { continue; };
            for &mid in mid_list {
                grouped.entry(mid as usize).or_default().insert(idx);
            }
        }

        let mut ret = Vec::new();
        let mut sorted_mids: Vec<&usize> = grouped.keys().collect();
        sorted_mids.sort();
        for mid in sorted_mids {
            let idx_set = &grouped[mid];
            let mut sorted_idxs: Vec<&usize> = idx_set.iter().collect();
            sorted_idxs.sort();
            let matched = sorted_idxs
                .iter()
                .map(|&&idx| self._format_matched_name(&dex, find_type, idx))
                .collect::<Vec<_>>()
                .join("; ");
            ret.push(format!(
                "{} | {} | matched=({})",
                dex_name,
                self._format_method(&dex, *mid),
                matched
            ));
        }
        ret
    }
}
