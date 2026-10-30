// Auth: MG1937
// Strict 1:1 translation from Python asc_handler.py

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::asc_core::core::dex::dex_manager::DexManager;
use crate::asc_core::findrefs::findrefs_manager::{
    FindRefInput, FindRefManager, FindRefResult,
};
use crate::asc_core::utils::decompiler::{
    decompile_dex_bytes, decompile_dex_bytes_with_metadata, MemberReference,
};
use crate::asc_core::utils::tinydex::DEX;

#[derive(Clone, Copy, Debug, Default)]
pub struct FindRefsDisplayOptions {
    pub max_match: Option<usize>,
    pub no_match: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FindRefJsonRecord {
    pub dex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub matched: Vec<String>,
}

fn truncate_chars(text: &str, max_chars: Option<usize>) -> String {
    let Some(limit) = max_chars else {
        return text.to_owned();
    };
    let mut chars = text.char_indices();
    if let Some((byte_idx, _)) = chars.nth(limit) {
        let mut out = text[..byte_idx].to_owned();
        out.push_str("...");
        out
    } else {
        text.to_owned()
    }
}

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
        let direct = decompile_dex_bytes(dex_buf, dalvik_class);
        if !direct.starts_with("/* RadGuard decompiler error:")
            && !direct.starts_with("Error: Class ")
        {
            if self.debug {
                eprintln!("[Decompiler] path=direct class={dalvik_class}");
            }
            return direct;
        }
        if self.debug {
            eprintln!(
                "[Decompiler] path=fallback reason={} class={dalvik_class}",
                direct.lines().next().unwrap_or("direct decompile failed")
            );
        }
        let mut manager = DexManager::from_bytes(dex_buf.to_vec(), self.debug);
        let new_dex_bytes = manager.extract_and_rebuild(dalvik_class);
        decompile_dex_bytes(&new_dex_bytes, dalvik_class)
    }

    pub fn getclass_with_metadata(
        &self,
        dex_buf: &[u8],
        dalvik_class: &str,
    ) -> (String, Vec<MemberReference>) {
        let (direct_source, direct_refs) = decompile_dex_bytes_with_metadata(dex_buf, dalvik_class);
        if !direct_source.starts_with("/* RadGuard decompiler error:")
            && !direct_source.starts_with("Error: Class ")
        {
            if self.debug {
                eprintln!("[Decompiler] path=direct class={dalvik_class}");
            }
            return (direct_source, direct_refs);
        }
        if self.debug {
            eprintln!(
                "[Decompiler] path=fallback reason={} class={dalvik_class}",
                direct_source
                    .lines()
                    .next()
                    .unwrap_or("direct decompile failed")
            );
        }
        let mut manager = DexManager::from_bytes(dex_buf.to_vec(), self.debug);
        let new_dex_bytes = manager.extract_and_rebuild(dalvik_class);
        decompile_dex_bytes_with_metadata(&new_dex_bytes, dalvik_class)
    }

    pub fn getclass_from_decompiler(
        &self,
        decompiler: &radguard::Decompiler<'_>,
        dex_buf: &[u8],
        dalvik_class: &str,
    ) -> (String, Vec<MemberReference>) {
        match decompiler.decompile_class(dalvik_class) {
            Ok(Some(output)) => {
                if self.debug {
                    eprintln!("[Decompiler] path=direct class={dalvik_class}");
                }
                (output.source, output.member_references)
            }
            Ok(None) => {
                if self.debug {
                    eprintln!(
                        "[Decompiler] path=fallback reason=class not found in direct DEX table class={dalvik_class}"
                    );
                }
                let mut manager = DexManager::from_bytes(dex_buf.to_vec(), self.debug);
                let new_dex_bytes = manager.extract_and_rebuild(dalvik_class);
                decompile_dex_bytes_with_metadata(&new_dex_bytes, dalvik_class)
            }
            Err(error) => {
                if self.debug {
                    eprintln!("[Decompiler] path=fallback reason={error} class={dalvik_class}");
                }
                let mut manager = DexManager::from_bytes(dex_buf.to_vec(), self.debug);
                let new_dex_bytes = manager.extract_and_rebuild(dalvik_class);
                decompile_dex_bytes_with_metadata(&new_dex_bytes, dalvik_class)
            }
        }
    }

    fn _format_method(&self, dex: &DEX, midx: usize) -> String {
        let method = dex.get_method(midx as u32);
        format!("{}->{}", method.cls().fullname, method.name())
    }

    fn _format_matched_name(&self, dex: &DEX, find_type: &str, idx: usize) -> String {
        match find_type {
            "string" => dex.get_string(idx).value,
            "type" => dex.get_type(idx as u32).descriptor,
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

    pub(crate) fn _findrefs(
        &self,
        dex_name: &str,
        dex: &DEX,
        find_type: &str,
        find: &FindRefInput,
        aggregate: bool,
    ) -> Vec<String> {
        self._findrefs_with_options(
            dex_name,
            dex,
            find_type,
            find,
            aggregate,
            FindRefsDisplayOptions::default(),
        )
    }

    pub(crate) fn _findrefs_with_options(
        &self,
        dex_name: &str,
        dex: &DEX,
        find_type: &str,
        find: &FindRefInput,
        aggregate: bool,
        display: FindRefsDisplayOptions,
    ) -> Vec<String> {
        let records = self._findrefs_records(dex_name, dex, find_type, find, aggregate, display);
        records
            .into_iter()
            .map(|record| {
                if let (Some(class), Some(relation), Some(target)) =
                    (record.class, record.relation, record.target)
                {
                    format!("{} | {} {} {}", record.dex, class, relation, target)
                } else {
                    let caller = record.caller.unwrap_or_default();
                    if display.no_match {
                        format!("{} | {}", record.dex, caller)
                    } else {
                        format!(
                            "{} | {} | matched=({})",
                            record.dex,
                            caller,
                            record.matched.join("; ")
                        )
                    }
                }
            })
            .collect()
    }

    pub(crate) fn _findrefs_records(
        &self,
        dex_name: &str,
        dex: &DEX,
        find_type: &str,
        find: &FindRefInput,
        aggregate: bool,
        display: FindRefsDisplayOptions,
    ) -> Vec<FindRefJsonRecord> {
        let mut ref_manager = FindRefManager::new(dex, self.debug);
        let profile = std::env::var_os("RASC_PROFILE").is_some();
        let tf0 = profile.then(std::time::Instant::now);
        let output = ref_manager.find_ref(find, true);
        let tf1 = profile.then(std::time::Instant::now);

        let Some(output) = output else {
            return Vec::new();
        };

        if profile {
            eprintln!(
                "[PROF] find_ref={:.3}ms",
                (tf1.unwrap() - tf0.unwrap()).as_secs_f64() * 1e3
            );
        }
        let out = match output {
            FindRefResult::ClassDefs(class_idxs) => {
                let (target, verb) = if find_type == "extends" {
                    (find.extends.as_deref(), "extends")
                } else {
                    (find.impl_.as_deref(), "implements")
                };
                let Some(target) = target else {
                    return Vec::new();
                };
                return class_idxs
                    .into_iter()
                    .map(|class_idx| FindRefJsonRecord {
                        dex: dex_name.to_owned(),
                        caller: None,
                        class: Some(dex.get_type(class_idx).descriptor),
                        relation: Some(verb.to_owned()),
                        target: Some(target.to_owned()),
                        matched: Vec::new(),
                    })
                    .collect();
            }
            FindRefResult::Refs(out) => out,
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

        let format_match = |idx: usize| -> String {
            let raw = self._format_matched_name(dex, find_type, idx);
            if find_type == "string" {
                truncate_chars(&raw, display.max_match)
            } else {
                raw
            }
        };

        if !aggregate {
            let mut ret = Vec::new();
            for (i, mid_entry) in mids.iter().enumerate() {
                let idx = matched_idxs.get(i).copied().unwrap_or(0);
                let matched = if display.no_match {
                    Vec::new()
                } else {
                    vec![format_match(idx)]
                };
                let Some(mid_list) = mid_entry else {
                    continue;
                };
                for &mid in mid_list {
                    ret.push(FindRefJsonRecord {
                        dex: dex_name.to_owned(),
                        caller: Some(self._format_method(dex, mid as usize)),
                        class: None,
                        relation: None,
                        target: None,
                        matched: matched.clone(),
                    });
                }
            }
            return ret;
        }

        // aggregate = true
        let mut grouped: HashMap<usize, HashSet<usize>> = HashMap::new();
        for (i, mid_entry) in mids.iter().enumerate() {
            let idx = matched_idxs.get(i).copied().unwrap_or(0);
            let Some(mid_list) = mid_entry else {
                continue;
            };
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
            let matched = if display.no_match {
                Vec::new()
            } else {
                sorted_idxs
                    .iter()
                    .map(|&&idx| format_match(idx))
                    .collect::<Vec<_>>()
            };
            ret.push(FindRefJsonRecord {
                dex: dex_name.to_owned(),
                caller: Some(self._format_method(dex, *mid)),
                class: None,
                relation: None,
                target: None,
                matched,
            });
        }
        ret
    }
}
