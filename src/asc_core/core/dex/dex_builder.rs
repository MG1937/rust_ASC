use std::collections::HashMap;
use std::time::Instant;

use crate::asc_core::utils::leb128::write_uleb128;
use crate::asc_core::utils::leb128::write_sleb128;
use crate::asc_core::utils::dex_parser::rebuild_annotation_item;
use crate::asc_core::utils::dex_parser::rebuild_encoded_array;
use crate::asc_core::utils::dex_parser::rebuild_debug_info;
use crate::asc_core::core::dex::dex_remapper::DexIndexMapper;
use crate::asc_core::core::dex::dex_constructor::DexHollower;

// Auth: MG1937
// dex builder is gen by LLM, I believe LLM can handle this well.. ;) 20260428

/// Read bytecode from raw DEX buffer at the given code_off
fn read_bytecode_from_raw(raw: &[u8], code_off: u32) -> Vec<u8> {
    if code_off == 0 {
        return Vec::new();
    }
    let off = code_off as usize;
    let insns_size = u16::from_le_bytes([raw[off + 12], raw[off + 13]]) as usize;
    let insns_start = off + 16;
    raw[insns_start..insns_start + insns_size * 2].to_vec()
}

/// Read class_data from raw DEX buffer and return categorized lists of field/method indices with metadata
fn read_class_data_from_raw(
    raw: &[u8],
    class_data_off: usize,
) -> (Vec<(u32, u32)>, Vec<(u32, u32)>, Vec<(u32, u32, u32)>, Vec<(u32, u32, u32)>) {
    // Returns (static_fields, instance_fields, direct_methods, virtual_methods)
    // Each field tuple: (field_idx, access_flags)
    // Each method tuple: (method_idx, access_flags, code_off)
    if class_data_off == 0 {
        return (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    }

    use crate::asc_core::utils::leb128::read_uleb128_fast;
    let mut p = class_data_off;

    let (s_f_cnt, c) = read_uleb128_fast(raw, p); p += c;
    let (i_f_cnt, c) = read_uleb128_fast(raw, p); p += c;
    let (d_m_cnt, c) = read_uleb128_fast(raw, p); p += c;
    let (v_m_cnt, c) = read_uleb128_fast(raw, p); p += c;

    let mut static_fields = Vec::with_capacity(s_f_cnt as usize);
    let mut instance_fields = Vec::with_capacity(i_f_cnt as usize);
    let mut direct_methods = Vec::with_capacity(d_m_cnt as usize);
    let mut virtual_methods = Vec::with_capacity(v_m_cnt as usize);

    // Static fields
    let mut last_idx: u32 = 0;
    for _ in 0..s_f_cnt {
        let (diff, c) = read_uleb128_fast(raw, p); p += c;
        last_idx += diff as u32;
        let (acc, c) = read_uleb128_fast(raw, p); p += c;
        static_fields.push((last_idx, acc as u32));
    }

    // Instance fields
    last_idx = 0;
    for _ in 0..i_f_cnt {
        let (diff, c) = read_uleb128_fast(raw, p); p += c;
        last_idx += diff as u32;
        let (acc, c) = read_uleb128_fast(raw, p); p += c;
        instance_fields.push((last_idx, acc as u32));
    }

    // Direct methods
    last_idx = 0;
    for _ in 0..d_m_cnt {
        let (diff, c) = read_uleb128_fast(raw, p); p += c;
        last_idx += diff as u32;
        let (acc, c) = read_uleb128_fast(raw, p); p += c;
        let (code_off, c) = read_uleb128_fast(raw, p); p += c;
        direct_methods.push((last_idx, acc as u32, code_off as u32));
    }

    // Virtual methods
    last_idx = 0;
    for _ in 0..v_m_cnt {
        let (diff, c) = read_uleb128_fast(raw, p); p += c;
        last_idx += diff as u32;
        let (acc, c) = read_uleb128_fast(raw, p); p += c;
        let (code_off, c) = read_uleb128_fast(raw, p); p += c;
        virtual_methods.push((last_idx, acc as u32, code_off as u32));
    }

    (static_fields, instance_fields, direct_methods, virtual_methods)
}

pub struct DexBuilder<'a, 'b> {
    pub im: &'b DexIndexMapper<'a>,
    pub hlw: &'b DexHollower<'a>,
    pub modified_bytecodes: &'b HashMap<u32, Vec<u8>>,
    pub out: Vec<u8>,
    pub debug: bool,
}

impl<'a, 'b> DexBuilder<'a, 'b> {
    pub fn new(im: &'b DexIndexMapper<'a>, hlw: &'b DexHollower<'a>, modified_bytecodes: &'b HashMap<u32, Vec<u8>>, debug: bool) -> Self {
        DexBuilder {
            im,
            hlw,
            modified_bytecodes,
            out: Vec::new(),
            debug,
        }
    }

    pub fn build(&mut self) -> Vec<u8> {
        let t_start = if self.debug { Some(Instant::now()) } else { None };

        // Layout of DEX:
        // Header: 0x70 bytes
        // String IDs
        // Type IDs
        // Proto IDs
        // Field IDs
        // Method IDs
        // Class Defs
        // Data Section (Strings, Types, Class Data, Code Items)
        // Map List

        self.out = vec![0u8; 112]; // 0x70

        // Create IndexMapper for rebuild functions
        let index_mapper = self.im.to_index_mapper();

        // 1. Write Data Section first
        // String Data
        let mut string_data_offs = Vec::new();
        for s in &self.im.str_restruct {
            string_data_offs.push(self.out.len() as u32);
            // MUTF-8 length
            let s_bytes = s.as_bytes();
            self.out.extend(write_uleb128(s.len() as u64)); // char length, approx len(s) for ascii
            self.out.extend(s_bytes);
            self.out.push(0);
        }

        let t_string_data = if self.debug { Some(Instant::now()) } else { None };

        // Type Lists (Interfaces & Protos)
        // Proto type lists
        let mut proto_param_offs = Vec::new();
        // align to 4
        while self.out.len() & 3 != 0 { self.out.push(0); }

        for proto in &self.im.proto_restruct {
            let params = &proto[3..];
            if params.is_empty() {
                proto_param_offs.push(0);
            } else {
                while self.out.len() & 3 != 0 { self.out.push(0); }
                proto_param_offs.push(self.out.len() as u32);
                self.out.extend((params.len() as u32).to_le_bytes());
                for &p in params {
                    self.out.extend((p as u16).to_le_bytes());
                }
            }
        }

        // Interface type list
        let mut ifs_off = 0u32;
        if !self.hlw.ifs_list_hlw_types.is_empty() {
            while self.out.len() & 3 != 0 { self.out.push(0); }
            ifs_off = self.out.len() as u32;
            let ifs_size = self.hlw.ifs_list_hlw_types[0];
            self.out.extend(ifs_size.to_le_bytes());
            for &t in &self.hlw.ifs_list_hlw_types[1..] {
                // remap interface type idx
                let key = (t as i64, -1i64);
                let new_t = self.im.type_restruct_idx.get(&key).copied().unwrap_or(0);
                self.out.extend((new_t as u16).to_le_bytes());
            }
        }

        let t_type_lists = if self.debug { Some(Instant::now()) } else { None };

        // Annotations
        let mut annotation_item_offs = HashMap::new();
        let mut annotation_set_offs = HashMap::new();
        let mut annotation_set_ref_offs = HashMap::new();
        let mut annotation_dir_off = 0u32;
        if let Some(ref anno_dir) = self.hlw.annotation_directory {
            // annotation items
            let mut anno_items_sorted: Vec<(&u32, &crate::asc_core::utils::dex_parser::AnnotationItem)> = self.hlw.annotation_items.iter().collect();
            anno_items_sorted.sort_by_key(|&(k, _)| *k);
            for &(&old_off, ref item) in &anno_items_sorted {
                annotation_item_offs.insert(old_off, self.out.len() as u32);
                self.out.extend(rebuild_annotation_item(item, &index_mapper));
            }

            // annotation sets
            while self.out.len() & 3 != 0 { self.out.push(0); }
            let mut anno_sets_sorted: Vec<(&u32, &crate::asc_core::core::dex::dex_constructor::AnnotationSet)> = self.hlw.annotation_sets.iter().collect();
            anno_sets_sorted.sort_by_key(|&(k, _)| *k);
            for &(&old_off, ref anno_set) in &anno_sets_sorted {
                annotation_set_offs.insert(old_off, self.out.len() as u32);
                // Sort items by type_idx
                let mut items_with_type: Vec<(u32, u32)> = anno_set.items.iter().map(|&item_off| {
                    let type_idx = if let Some(ann_item) = self.hlw.annotation_items.get(&item_off) {
                        let key = (ann_item.annotation.type_idx as i64, -1i64);
                        self.im.type_restruct_idx.get(&key).copied().unwrap_or(0)
                    } else { 0 };
                    (type_idx, item_off)
                }).collect();
                items_with_type.sort_by_key(|&(t, _)| t);
                self.out.extend((items_with_type.len() as u32).to_le_bytes());
                for (_type_idx, item_off) in &items_with_type {
                    self.out.extend(annotation_item_offs.get(item_off).copied().unwrap_or(0).to_le_bytes());
                }
            }

            // annotation set refs
            while self.out.len() & 3 != 0 { self.out.push(0); }
            let mut anno_refs_sorted: Vec<(&u32, &Vec<u32>)> = self.hlw.annotation_set_refs.iter().collect();
            anno_refs_sorted.sort_by_key(|&(k, _)| *k);
            for &(&old_off, ref refs) in &anno_refs_sorted {
                annotation_set_ref_offs.insert(old_off, self.out.len() as u32);
                self.out.extend((refs.len() as u32).to_le_bytes());
                for &set_off in *refs {
                    self.out.extend(annotation_set_offs.get(&set_off).copied().unwrap_or(0).to_le_bytes());
                }
            }

            while self.out.len() & 3 != 0 { self.out.push(0); }
            annotation_dir_off = self.out.len() as u32;

            // Build field_annotations, method_annotations, parameter_annotations with remapped indices
            let mut field_annotations: Vec<(u32, u32)> = anno_dir.field_annotations.iter()
                .filter(|(field_idx, _)| self.im.field_restruct_idx.contains_key(field_idx))
                .map(|(field_idx, set_off)| (self.im.field_restruct_idx[field_idx], *set_off))
                .collect();
            field_annotations.sort_by_key(|&(idx, _)| idx);

            let mut method_annotations: Vec<(u32, u32)> = anno_dir.method_annotations.iter()
                .filter(|(method_idx, _)| self.im.method_restruct_idx.contains_key(method_idx))
                .map(|(method_idx, set_off)| (self.im.method_restruct_idx[method_idx], *set_off))
                .collect();
            method_annotations.sort_by_key(|&(idx, _)| idx);

            let mut parameter_annotations: Vec<(u32, u32)> = anno_dir.parameter_annotations.iter()
                .filter(|(method_idx, _)| self.im.method_restruct_idx.contains_key(method_idx))
                .map(|(method_idx, ref_off)| (self.im.method_restruct_idx[method_idx], *ref_off))
                .collect();
            parameter_annotations.sort_by_key(|&(idx, _)| idx);

            self.out.extend(annotation_set_offs.get(&anno_dir.class_annotations_off).copied().unwrap_or(0).to_le_bytes());
            self.out.extend((field_annotations.len() as u32).to_le_bytes());
            self.out.extend((method_annotations.len() as u32).to_le_bytes());
            self.out.extend((parameter_annotations.len() as u32).to_le_bytes());

            for (field_idx, set_off) in field_annotations {
                self.out.extend(field_idx.to_le_bytes());
                self.out.extend(annotation_set_offs.get(&set_off).copied().unwrap_or(0).to_le_bytes());
            }
            for (method_idx, set_off) in method_annotations {
                self.out.extend(method_idx.to_le_bytes());
                self.out.extend(annotation_set_offs.get(&set_off).copied().unwrap_or(0).to_le_bytes());
            }
            for (method_idx, ref_off) in parameter_annotations {
                self.out.extend(method_idx.to_le_bytes());
                self.out.extend(annotation_set_ref_offs.get(&ref_off).copied().unwrap_or(0).to_le_bytes());
            }
        }

        // Static Values
        let mut static_values_off = 0u32;
        if self.hlw.static_values_elements.is_some() {
            while self.out.len() & 3 != 0 { self.out.push(0); }
            static_values_off = self.out.len() as u32;
            // rebuild_encoded_array expects the elements and mapper
            let elements_ref = self.hlw.static_values_elements.as_ref().unwrap();
            self.out.extend(rebuild_encoded_array(elements_ref, &index_mapper));
        }

        let t_static_values = if self.debug { Some(Instant::now()) } else { None };

        // Code Items and Debug Info
        // Pre-read method code_offs from raw class_data for bytecode fallback reading
        let clz_def_data_code: Vec<u32> = self.hlw.clz_raw_byte.chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let raw_class_data_off_code = clz_def_data_code[6] as usize;
        let (_, _, raw_d_m_code, raw_v_m_code) = read_class_data_from_raw(self.hlw._raw_cache, raw_class_data_off_code);
        let mut method_code_offs: HashMap<u32, u32> = HashMap::new();
        for &(m_idx, _, code_off) in &raw_d_m_code { method_code_offs.insert(m_idx, code_off); }
        for &(m_idx, _, code_off) in &raw_v_m_code { method_code_offs.insert(m_idx, code_off); }

        let mut code_item_offs: HashMap<u32, u32> = HashMap::new(); // { method_idx: off }
        let mut debug_info_offs = Vec::new();

        // First, write all debug info
        let mut method_to_debug_off: HashMap<u32, u32> = HashMap::new();
        let mut methods_with_code: Vec<u32> = self.im.methods_obj.iter()
            .filter(|&&idx| self.hlw.code_item_hlws.contains_key(&idx))
            .copied()
            .collect();
        methods_with_code.sort_by_key(|&idx| self.im.method_restruct_idx.get(&idx).copied().unwrap_or(0));

        for &method_idx in &methods_with_code {
            if let Some(debug_info) = self.hlw.debug_info_items.get(&method_idx) {
                let debug_info_off = self.out.len() as u32;
                method_to_debug_off.insert(method_idx, debug_info_off);
                debug_info_offs.push(debug_info_off);
                self.out.extend(rebuild_debug_info(debug_info, &index_mapper));
            }
        }

        // Pre-compute aligned code_offs from code_item_hlws header data
        // The header at offset 12-16 contains insns_size, and we need to know where
        // the original code was to read bytecode as fallback
        let raw = self.hlw._raw_cache;

        // Then, write all code items
        for &method_idx in &methods_with_code {
            let debug_info_off = method_to_debug_off.get(&method_idx).copied().unwrap_or(0);

            // Let's align code_item to 4 bytes FIRST
            while self.out.len() & 3 != 0 { self.out.push(0); }
            code_item_offs.insert(method_idx, self.out.len() as u32);

            // code item bytes
            let code_item_info = self.hlw.code_item_hlws.get(&method_idx).unwrap();
            let orig_header = &code_item_info.0;
            let try_item_bytes = code_item_info.1.as_ref();
            let tries_size = code_item_info.2;

            // Read bytecode: use modified if available, otherwise read from raw DEX
            let bc = if let Some(bc) = self.modified_bytecodes.get(&method_idx) {
                bc.clone()
            } else if let Some(&code_off) = method_code_offs.get(&method_idx) {
                if code_off > 0 {
                    let off = (code_off as usize + 3) & !3; // align to 4
                    let insns_size = u32::from_le_bytes([
                        raw[off + 12],
                        raw[off + 13],
                        raw[off + 14],
                        raw[off + 15],
                    ]) as usize;
                    let insns_start = off + 16;
                    raw[insns_start..insns_start + insns_size * 2].to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            let insns_size = bc.len() / 2;

            let (_debug_val, catch_handler_list_opt) = self.hlw.code_item_metadata_hlws.get(&method_idx)
                .map(|(d, c)| (*d, c.as_ref()))
                .unwrap_or((0, None));

            let mut new_header = orig_header.clone();
            new_header[8..12].copy_from_slice(&debug_info_off.to_le_bytes());
            new_header[12..16].copy_from_slice(&(insns_size as u32).to_le_bytes());
            self.out.extend(&new_header);
            self.out.extend(&bc);

            if tries_size > 0 {
                if insns_size & 1 != 0 {
                    self.out.extend(&[0x00, 0x00]);
                }

                let mut new_handlers_bytes = Vec::new();
                let mut old_to_new_offset: HashMap<u32, u32> = HashMap::new();

                if let Some(catch_handler_list) = catch_handler_list_opt {
                    new_handlers_bytes.extend(write_uleb128(catch_handler_list[0][0] as u64));
                    for i in 1..catch_handler_list.len() {
                        let handler = &catch_handler_list[i];
                        let old_off = handler[0];
                        let h_size = handler[1] as i32;

                        // bugfix, need to update catch handler off,
                        // or old handler off may not fit new list due to length change by uleb128 rewrite 20260730
                        old_to_new_offset.insert(old_off, new_handlers_bytes.len() as u32);

                        new_handlers_bytes.extend(write_sleb128(h_size as i64));
                        let mut pos = 2;
                        for _ in 0..h_size.unsigned_abs() {
                            new_handlers_bytes.extend(write_uleb128(handler[pos] as u64)); // type_idx
                            new_handlers_bytes.extend(write_uleb128(handler[pos + 1] as u64)); // addr
                            pos += 2;
                        }
                        if h_size <= 0 {
                            new_handlers_bytes.extend(write_uleb128(handler[pos] as u64)); // catch_all_addr
                        }
                    }
                }

                let try_item_bytes = try_item_bytes.unwrap();
                let mut new_try_item_bytes = Vec::new();
                for j in 0..tries_size as usize {
                    let old_handler_off = u16::from_le_bytes([try_item_bytes[j * 8 + 6], try_item_bytes[j * 8 + 7]]) as u32;
                    let new_handler_off = old_to_new_offset.get(&old_handler_off).copied().unwrap_or(old_handler_off);

                    new_try_item_bytes.extend(&try_item_bytes[j * 8..j * 8 + 6]);
                    new_try_item_bytes.extend((new_handler_off as u16).to_le_bytes());
                }

                self.out.extend(&new_try_item_bytes);
                self.out.extend(&new_handlers_bytes);
            }
        }

        let t_code_items = if self.debug { Some(Instant::now()) } else { None };

        // Class Data Item
        let mut class_data_off = 0u32;
        if !self.im.fields_obj.is_empty() || !self.im.methods_obj.is_empty() {
            // Read class data from raw DEX to get proper access_flags and categorization
            let clz_def_data: Vec<u32> = self.hlw.clz_raw_byte.chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            let raw_class_data_off = clz_def_data[6] as usize;

            let (mut raw_s_f, mut raw_i_f, mut raw_d_m, mut raw_v_m) =
                read_class_data_from_raw(self.hlw._raw_cache, raw_class_data_off);

            raw_s_f.sort_by_key(|(f_idx, _)| {
                self.im.field_restruct_idx.get(f_idx).copied().unwrap_or(u32::MAX)
            });
            raw_i_f.sort_by_key(|(f_idx, _)| {
                self.im.field_restruct_idx.get(f_idx).copied().unwrap_or(u32::MAX)
            });
            raw_d_m.sort_by_key(|(m_idx, _, _)| {
                self.im.method_restruct_idx.get(m_idx).copied().unwrap_or(u32::MAX)
            });
            raw_v_m.sort_by_key(|(m_idx, _, _)| {
                self.im.method_restruct_idx.get(m_idx).copied().unwrap_or(u32::MAX)
            });

            class_data_off = self.out.len() as u32;

            // count
            self.out.extend(write_uleb128(raw_s_f.len() as u64));
            self.out.extend(write_uleb128(raw_i_f.len() as u64));
            self.out.extend(write_uleb128(raw_d_m.len() as u64));
            self.out.extend(write_uleb128(raw_v_m.len() as u64));

            // write static fields
            {
                let mut last_idx: u32 = 0;
                for &(f_idx, acc) in &raw_s_f {
                    let new_idx = self.im.field_restruct_idx[&f_idx];
                    let idx_diff = new_idx.checked_sub(last_idx)
                        .expect("static field indices are not sorted");
                    self.out.extend(write_uleb128(idx_diff as u64));
                    last_idx = new_idx;
                    self.out.extend(write_uleb128(acc as u64));
                }
            }

            // write instance fields
            {
                let mut last_idx: u32 = 0;
                for &(f_idx, acc) in &raw_i_f {
                    let new_idx = self.im.field_restruct_idx[&f_idx];
                    let idx_diff = new_idx.checked_sub(last_idx)
                        .expect("instance field indices are not sorted");
                    self.out.extend(write_uleb128(idx_diff as u64));
                    last_idx = new_idx;
                    self.out.extend(write_uleb128(acc as u64));
                }
            }

            // write direct methods
            {
                let mut last_idx: u32 = 0;
                for &(m_idx, acc, _) in &raw_d_m {
                    let new_idx = self.im.method_restruct_idx[&m_idx];
                    let idx_diff = new_idx.checked_sub(last_idx)
                        .expect("direct method indices are not sorted");
                    self.out.extend(write_uleb128(idx_diff as u64));
                    last_idx = new_idx;
                    self.out.extend(write_uleb128(acc as u64));
                    let c_off = code_item_offs.get(&m_idx).copied().unwrap_or(0);
                    self.out.extend(write_uleb128(c_off as u64));
                }
            }

            // write virtual methods
            {
                let mut last_idx: u32 = 0;
                for &(m_idx, acc, _) in &raw_v_m {
                    let new_idx = self.im.method_restruct_idx[&m_idx];
                    let idx_diff = new_idx.checked_sub(last_idx)
                        .expect("virtual method indices are not sorted");
                    self.out.extend(write_uleb128(idx_diff as u64));
                    last_idx = new_idx;
                    self.out.extend(write_uleb128(acc as u64));
                    let c_off = code_item_offs.get(&m_idx).copied().unwrap_or(0);
                    self.out.extend(write_uleb128(c_off as u64));
                }
            }
        }

        let t_class_data = if self.debug { Some(Instant::now()) } else { None };

        // Now write IDs
        // Align 4
        while self.out.len() & 3 != 0 { self.out.push(0); }

        // String IDs
        let string_ids_off = self.out.len() as u32;
        if !string_data_offs.is_empty() {
            for &off in &string_data_offs {
                self.out.extend(off.to_le_bytes());
            }
        }

        // Type IDs
        let type_ids_off = self.out.len() as u32;
        if !self.im.type_restruct.is_empty() {
            for &val in &self.im.type_restruct {
                self.out.extend(val.to_le_bytes());
            }
        }

        // Proto IDs
        let proto_ids_off = self.out.len() as u32;
        if !self.im.proto_restruct.is_empty() {
            for i in 0..self.im.proto_restruct.len() {
                self.out.extend(self.im.proto_restruct[i][0].to_le_bytes());
                self.out.extend(self.im.proto_restruct[i][1].to_le_bytes());
                self.out.extend(proto_param_offs[i].to_le_bytes());
            }
        }

        // Field IDs
        let field_ids_off = self.out.len() as u32;
        if !self.im.field_restruct.is_empty() {
            for fld in &self.im.field_restruct {
                self.out.extend((fld[0] | (fld[1] << 16)).to_le_bytes());
                self.out.extend(fld[2].to_le_bytes());
            }
        }

        // Method IDs
        let method_ids_off = self.out.len() as u32;
        if !self.im.method_restruct.is_empty() {
            for mth in &self.im.method_restruct {
                self.out.extend((mth[0] | (mth[1] << 16)).to_le_bytes());
                self.out.extend(mth[2].to_le_bytes());
            }
        }

        // Class Defs
        let class_defs_off = self.out.len() as u32;
        let clz_def_data: Vec<u32> = self.hlw.clz_raw_byte.chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        let key_0 = (clz_def_data[0] as i64, -1i64);
        let clz_idx = self.im.type_restruct_idx.get(&key_0).copied().unwrap_or(0);

        let acc_flags = clz_def_data[1];

        let key_super = (clz_def_data[2] as i64, -1i64);
        let super_idx = self.im.type_restruct_idx.get(&key_super).copied().unwrap_or(0xffffffff);

        let src_idx = if clz_def_data[4] != 0xffffffff {
            let src_str = &self.im.origin_strings[clz_def_data[4] as usize];
            self.im.str_restruct_idx.get(src_str).copied().unwrap_or(0xffffffff)
        } else {
            0xffffffff
        };

        let class_def_vals = [clz_idx, acc_flags, super_idx, ifs_off, src_idx, annotation_dir_off, class_data_off, static_values_off];
        for &val in &class_def_vals {
            self.out.extend(val.to_le_bytes());
        }

        let t_ids = if self.debug { Some(Instant::now()) } else { None };

        // Map List
        while self.out.len() & 3 != 0 { self.out.push(0); }
        let map_list_off = self.out.len() as u32;

        // Map items
        let mut map_items: Vec<(u32, u32, u32)> = Vec::new(); // (type, size, offset)
        map_items.push((0x0000, 1, 0)); // Header
        if !self.im.str_restruct.is_empty() {
            map_items.push((0x0001, self.im.str_restruct.len() as u32, string_ids_off));
            map_items.push((0x2002, self.im.str_restruct.len() as u32, string_data_offs[0]));
        }
        if !self.im.type_restruct.is_empty() {
            map_items.push((0x0002, self.im.type_restruct.len() as u32, type_ids_off));
        }
        if !self.im.proto_restruct.is_empty() {
            map_items.push((0x0003, self.im.proto_restruct.len() as u32, proto_ids_off));
        }
        if !self.im.field_restruct.is_empty() {
            map_items.push((0x0004, self.im.field_restruct.len() as u32, field_ids_off));
        }
        if !self.im.method_restruct.is_empty() {
            map_items.push((0x0005, self.im.method_restruct.len() as u32, method_ids_off));
        }
        map_items.push((0x0006, 1, class_defs_off));

        // TYPE_TYPE_LIST (0x1001)
        let mut type_list_count = 0u32;
        let mut first_type_list_off = 0u32;
        if ifs_off > 0 {
            type_list_count += 1;
            first_type_list_off = ifs_off;
        }
        let valid_proto_param_offs: Vec<u32> = proto_param_offs.iter().filter(|&&off| off > 0).copied().collect();
        if !valid_proto_param_offs.is_empty() {
            type_list_count += valid_proto_param_offs.len() as u32;
            let min_off = *valid_proto_param_offs.iter().min().unwrap();
            if first_type_list_off == 0 || min_off < first_type_list_off {
                first_type_list_off = min_off;
            }
        }
        if type_list_count > 0 {
            map_items.push((0x1001, type_list_count, first_type_list_off));
        }

        if !annotation_set_ref_offs.is_empty() {
            let min_off = *annotation_set_ref_offs.values().min().unwrap();
            map_items.push((0x1002, annotation_set_ref_offs.len() as u32, min_off));
        }
        if !annotation_set_offs.is_empty() {
            let min_off = *annotation_set_offs.values().min().unwrap();
            map_items.push((0x1003, annotation_set_offs.len() as u32, min_off));
        }
        if annotation_dir_off > 0 {
            map_items.push((0x2006, 1, annotation_dir_off));
        }
        if !annotation_item_offs.is_empty() {
            let min_off = *annotation_item_offs.values().min().unwrap();
            map_items.push((0x2004, annotation_item_offs.len() as u32, min_off));
        }

        if class_data_off > 0 {
            map_items.push((0x2000, 1, class_data_off));
        }
        if !code_item_offs.is_empty() {
            let min_off = *code_item_offs.values().min().unwrap();
            map_items.push((0x2001, code_item_offs.len() as u32, min_off));
        }

        // TYPE_DEBUG_INFO_ITEM (0x2003)
        if !debug_info_offs.is_empty() {
            let min_off = *debug_info_offs.iter().min().unwrap();
            map_items.push((0x2003, debug_info_offs.len() as u32, min_off));
        }

        // TYPE_ENCODED_ARRAY_ITEM (0x2005)
        if static_values_off > 0 {
            map_items.push((0x2005, 1, static_values_off));
        }

        // Sort map_items by offset
        map_items.sort_by_key(|&(_, _, off)| off);
        map_items.push((0x1000, 1, map_list_off)); // Map List itself

        self.out.extend((map_items.len() as u32).to_le_bytes());

        // Map item is: type(2), unused(2), size(4), offset(4)
        for &(typ, size, offset) in &map_items {
            self.out.extend(typ.to_le_bytes()); // type + unused (since little endian, type is lower 16 bits, unused is 0)
            self.out.extend(size.to_le_bytes());
            self.out.extend(offset.to_le_bytes());
        }

        let t_map_list = if self.debug { Some(Instant::now()) } else { None };

        let file_size = self.out.len() as u32;

        // Header Patching
        // magic
        self.out[0..8].copy_from_slice(b"dex\n035\0");
        // file_size
        self.out[32..36].copy_from_slice(&file_size.to_le_bytes());
        // header_size
        self.out[36..40].copy_from_slice(&(0x70u32).to_le_bytes());
        // endian_tag
        self.out[40..44].copy_from_slice(&(0x12345678u32).to_le_bytes());
        // map_off
        self.out[52..56].copy_from_slice(&map_list_off.to_le_bytes());
        // string_ids: [size(4), offset(4)]
        self.out[56..60].copy_from_slice(&(self.im.str_restruct.len() as u32).to_le_bytes());
        self.out[60..64].copy_from_slice(&string_ids_off.to_le_bytes());
        // type_ids: [size(4), offset(4)]
        self.out[64..68].copy_from_slice(&(self.im.type_restruct.len() as u32).to_le_bytes());
        self.out[68..72].copy_from_slice(&type_ids_off.to_le_bytes());
        // proto_ids: [size(4), offset(4)]
        self.out[72..76].copy_from_slice(&(self.im.proto_restruct.len() as u32).to_le_bytes());
        self.out[76..80].copy_from_slice(&proto_ids_off.to_le_bytes());
        // field_ids: [size(4), offset(4)]
        self.out[80..84].copy_from_slice(&(self.im.field_restruct.len() as u32).to_le_bytes());
        self.out[84..88].copy_from_slice(&field_ids_off.to_le_bytes());
        // method_ids: [size(4), offset(4)]
        self.out[88..92].copy_from_slice(&(self.im.method_restruct.len() as u32).to_le_bytes());
        self.out[92..96].copy_from_slice(&method_ids_off.to_le_bytes());
        // class_defs: [size(4), offset(4)]
        self.out[96..100].copy_from_slice(&1u32.to_le_bytes());
        self.out[100..104].copy_from_slice(&class_defs_off.to_le_bytes());
        // data_size, data_off: [size(4), offset(4)]
        self.out[104..108].copy_from_slice(&(file_size - 0x70).to_le_bytes());
        self.out[108..112].copy_from_slice(&0x70u32.to_le_bytes());

        // signature
        self.out[12..32].copy_from_slice(&[0u8; 20]);
        // checksum
        self.out[8..12].copy_from_slice(&[0u8; 4]);

        if self.debug {
            let t_header = Instant::now();
            let t_start = t_start.unwrap();
            let t_string_data = t_string_data.unwrap();
            let t_type_lists = t_type_lists.unwrap();
            let t_static_values = t_static_values.unwrap();
            let t_code_items = t_code_items.unwrap();
            let t_class_data = t_class_data.unwrap();
            let t_ids = t_ids.unwrap();
            let t_map_list = t_map_list.unwrap();
            println!("[DexBuilder Profiler]");
            println!("  String Data: {:.2} us", (t_string_data - t_start).as_secs_f64() * 1000000.0);
            println!("  Type Lists:  {:.2} us", (t_type_lists - t_string_data).as_secs_f64() * 1000000.0);
            println!("  Static Vals: {:.2} us", (t_static_values - t_type_lists).as_secs_f64() * 1000000.0);
            println!("  Code & DBG:  {:.2} us", (t_code_items - t_static_values).as_secs_f64() * 1000000.0);
            println!("  Class Data:  {:.2} us", (t_class_data - t_code_items).as_secs_f64() * 1000000.0);
            println!("  IDs:         {:.2} us", (t_ids - t_class_data).as_secs_f64() * 1000000.0);
            println!("  Map List:    {:.2} us", (t_map_list - t_ids).as_secs_f64() * 1000000.0);
            println!("  Header:      {:.2} us", (t_header - t_map_list).as_secs_f64() * 1000000.0);
            println!("  Total Build: {:.2} us", (t_header - t_start).as_secs_f64() * 1000000.0);
        }

        std::mem::take(&mut self.out)
    }
}
