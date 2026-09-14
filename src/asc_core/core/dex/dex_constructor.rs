use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Instant;

use crate::asc_core::utils::leb128::read_uleb128_fast;
use crate::asc_core::utils::leb128::read_sleb128;
use crate::asc_core::utils::leb128::read_uleb128_len;
use crate::asc_core::utils::dex_parser::parse_encoded_array;
use crate::asc_core::utils::dex_parser::parse_debug_info;
use crate::asc_core::utils::dex_parser::parse_annotation_item;
use crate::asc_core::utils::dex_parser::DebugInfo;
use crate::asc_core::utils::dex_parser::AnnotationItem;
use crate::asc_core::utils::dex_parser::EncodedValue;
use crate::asc_core::utils::tinydex::DEX;

// Auth: MG1937
// Reconstruct DEX bytes, fill necessary fields

pub struct DexHollower<'a> {
    // Extract All bytes of specfic item
    // Hollow out all necessray fields, reconstruct it

    pub debug: bool,
    pub dex: &'a DEX,
    pub _raw_cache: &'a [u8],
    pub clz_idx: u32,

    // === hollow list ===
    pub clz_def_hlw_types: HashMap<u32, u32>, // {relative_offset:idx, ...}
    pub clz_def_hlw_strs: HashMap<u32, u32>, // {relative_offset:idx, ...}

    pub ifs_list_hlw_types: Vec<u32>, // [ifs_size, typeidx, ...]

    pub anno_dir_hlw_types: HashMap<u32, u32>, // {relative_offset:idx, ...}

    // hollow clz data wont help speed up build dex, just deprecated it 20260730
    pub clz_data_item_hlws: Vec<(u32, u32, u64, usize)>, // [(relative_offset,HLW_TYPE,value,leb128len), ...]
    pub clz_data_item_bytes: Option<Vec<u8>>,

    // adjust for builder
    pub code_item_hlws: HashMap<u32, (Vec<u8>, Option<Vec<u8>>, u32)>, // {method_idx: (code_item_bytes, try_item_bytes, tries_size)}
    pub code_item_metadata_hlws: HashMap<u32, (u32, Option<Vec<Vec<u32>>>)>, // {method_idx: (debug_off_pos, encoded_catch_handler_list)}

    pub static_values_elements: Option<Vec<EncodedValue>>,
    pub debug_info_items: HashMap<u32, DebugInfo>, // { method_idx: debug_info }
    pub annotation_directory: Option<AnnotationDirectory>,
    pub annotation_sets: HashMap<u32, AnnotationSet>, // { set_off: {items: [annotation_off, ...]} }
    pub annotation_items: HashMap<u32, AnnotationItem>, // { annotation_off: parsed_annotation_item }
    pub annotation_set_refs: HashMap<u32, Vec<u32>>, // { ref_list_off: [annotation_set_off, ...] }

    // New generic hollow lists for parsing static values and debug info
    // LLM added it for static value parser, but I dont think we will need it hhhh 20260729
    pub hlw_strs: HashSet<u32>,
    pub hlw_types: HashSet<u32>,
    pub hlw_fields: HashSet<u32>,
    pub hlw_methods: HashSet<u32>,

    pub clz_def_offset: usize,
    pub clz_raw_byte: Vec<u8>,
}

#[derive(Clone)]
pub struct AnnotationSet {
    pub items: Vec<u32>,
}

#[derive(Clone)]
pub struct AnnotationDirectory {
    pub class_annotations_off: u32,
    pub field_annotations: Vec<(u32, u32)>, // (field_idx, annotations_off)
    pub method_annotations: Vec<(u32, u32)>, // (method_idx, annotations_off)
    pub parameter_annotations: Vec<(u32, u32)>, // (method_idx, annotations_off)
}

impl<'a> DexHollower<'a> {
    pub fn new(dex: &'a DEX, dex_buffer: &'a [u8], clz_str: &str, debug: bool) -> Self {
        let t_start = if debug { Some(Instant::now()) } else { None };

        let clz = dex.get_class(clz_str).expect("Class not found in DEX");
        let t_get_class = if debug { Some(Instant::now()) } else { None };
        let clz_idx = clz.index;
        let t_index = if debug { Some(Instant::now()) } else { None };

        let clz_def_offset = (dex.header.classes.0 + clz_idx * 0x20) as usize;
        let clz_raw_byte = dex_buffer[clz_def_offset..clz_def_offset + 0x20].to_vec(); // class_def_item size == 0x20

        if debug {
            let t_end = Instant::now();
            let t_start = t_start.unwrap();
            let t_get_class = t_get_class.unwrap();
            let t_index = t_index.unwrap();
            println!("[DexHollower Init Profiler]");
            println!("  get_class: {:.2} us", (t_get_class - t_start).as_secs_f64() * 1000000.0);
            println!("  clz_index: {:.2} us", (t_index - t_get_class).as_secs_f64() * 1000000.0);
            println!("  rest:      {:.2} us", (t_end - t_index).as_secs_f64() * 1000000.0);
        }

        DexHollower {
            debug,
            dex,
            _raw_cache: dex_buffer,
            clz_idx,
            clz_def_hlw_types: HashMap::new(),
            clz_def_hlw_strs: HashMap::new(),
            ifs_list_hlw_types: Vec::new(),
            anno_dir_hlw_types: HashMap::new(),
            clz_data_item_hlws: Vec::new(),
            clz_data_item_bytes: None,
            code_item_hlws: HashMap::new(),
            code_item_metadata_hlws: HashMap::new(),
            static_values_elements: None,
            debug_info_items: HashMap::new(),
            annotation_directory: None,
            annotation_sets: HashMap::new(),
            annotation_items: HashMap::new(),
            annotation_set_refs: HashMap::new(),
            hlw_strs: HashSet::new(),
            hlw_types: HashSet::new(),
            hlw_fields: HashSet::new(),
            hlw_methods: HashSet::new(),
            clz_def_offset,
            clz_raw_byte,
        }
    }

    fn _hollow_interface_bytes(&mut self, ifs_off: usize) -> u32 {
        if ifs_off == 0 {
            return 0;
        }
        // ifs size
        let ifs_size = u32::from_le_bytes([self._raw_cache[ifs_off], self._raw_cache[ifs_off+1], self._raw_cache[ifs_off+2], self._raw_cache[ifs_off+3]]);
        self.ifs_list_hlw_types.push(ifs_size);

        let ifs_bytes = &self._raw_cache[ifs_off + 4..ifs_off + 4 + ifs_size as usize * 2];
        // Read u16 values
        for i in 0..ifs_size as usize {
            let val = u16::from_le_bytes([ifs_bytes[i*2], ifs_bytes[i*2+1]]) as u32;
            self.ifs_list_hlw_types.push(val);
        }
        ifs_size
    }

    // LLM write too much hollow redundant logic, I rewrited it 20260730
    fn _hollow_class_data_item_bytes(&mut self, off: usize) -> u32 {
        if off == 0 { return 0; }
        let data = self._raw_cache;
        let mut p = off;

        // Header
        let (s_f_cnt, c) = read_uleb128_fast(data, p); p += c;
        let (i_f_cnt, c) = read_uleb128_fast(data, p); p += c;
        let (d_m_cnt, c) = read_uleb128_fast(data, p); p += c;
        let (v_m_cnt, c) = read_uleb128_fast(data, p); p += c;

        // Skip Fields
        for _ in 0..(s_f_cnt + i_f_cnt) as usize {
            p += read_uleb128_len(data, p);
            p += read_uleb128_len(data, p);
        }

        // Direct Methods
        let mut last_idx: u32 = 0;
        for _ in 0..d_m_cnt as usize {
            let (diff, c) = read_uleb128_fast(data, p);
            last_idx += diff as u32;
            p += c;
            p += read_uleb128_len(data, p); // skip acc

            // code_off
            let (val, c) = read_uleb128_fast(data, p);
            p += c;

            if val > 0 {
                // Let's align code_off to 4 bytes because Dalvik requires code_item to be 4-byte aligned
                // 20260429 LLM add it, I am not familiar with alignment details...
                // 20260607 leave the code here, document requires 4 bytes alignment
                // https://source.android.com/docs/core/runtime/dex-format?hl=zh-cn#type-id-item
                let aligned_val = ((val as u32 + 3) & !3) as usize;
                let code_item_head = data[aligned_val..aligned_val + 16].to_vec();
                // 20260827 bugfix for misuse of 2 bytes unpacker, debug_info_off should be 4 bytes..
                let debug_val = u32::from_le_bytes([code_item_head[8], code_item_head[9], code_item_head[10], code_item_head[11]]);
                let tries_size = u16::from_le_bytes([code_item_head[6], code_item_head[7]]) as u32;
                let (try_item_bytes, encoded_catch_handler_list) = if tries_size != 0 { // try catch bugfix 20260730
                    let insns_size = u16::from_le_bytes([code_item_head[12], code_item_head[13]]) as u32;
                    let insns_end = aligned_val + 16 + insns_size as usize * 2;
                    let try_off = (insns_end + 3) & !3; // 4 bytes aligned
                    let try_off_end = try_off + tries_size as usize * 8;
                    let try_item_bytes = data[try_off..try_off_end].to_vec();
                    let encoded_catch_handler_list = self._hollow_encoded_catch_handler_list(data, try_off_end);
                    (Some(try_item_bytes), Some(encoded_catch_handler_list))
                } else {
                    (None, None)
                };
                self.code_item_hlws.insert(last_idx, (code_item_head, try_item_bytes, tries_size));
                self.code_item_metadata_hlws.insert(last_idx, (debug_val, encoded_catch_handler_list));
            }
        }

        // Virtual Methods
        last_idx = 0;
        for _ in 0..v_m_cnt as usize {
            let (diff, c) = read_uleb128_fast(data, p);
            last_idx += diff as u32;
            p += c;
            p += read_uleb128_len(data, p); // skip acc

            // code_off
            let (val, c) = read_uleb128_fast(data, p);
            p += c;

            if val > 0 {
                let aligned_val = ((val as u32 + 3) & !3) as usize;
                let code_item_head = data[aligned_val..aligned_val + 16].to_vec();
                let debug_val = u32::from_le_bytes([code_item_head[8], code_item_head[9], code_item_head[10], code_item_head[11]]);
                let tries_size = u16::from_le_bytes([code_item_head[6], code_item_head[7]]) as u32;
                let (try_item_bytes, encoded_catch_handler_list) = if tries_size != 0 {
                    let insns_size = u16::from_le_bytes([code_item_head[12], code_item_head[13]]) as u32;
                    let insns_end = aligned_val + 16 + insns_size as usize * 2;
                    let try_off = (insns_end + 3) & !3;
                    let try_off_end = try_off + tries_size as usize * 8;
                    let try_item_bytes = data[try_off..try_off_end].to_vec();
                    let encoded_catch_handler_list = self._hollow_encoded_catch_handler_list(data, try_off_end);
                    (Some(try_item_bytes), Some(encoded_catch_handler_list))
                } else {
                    (None, None)
                };
                self.code_item_hlws.insert(last_idx, (code_item_head, try_item_bytes, tries_size));
                self.code_item_metadata_hlws.insert(last_idx, (debug_val, encoded_catch_handler_list));
            }
        }
        // self.clz_data_item_bytes = data[off : p];
        0
    }

    // I dont handle try item and catch handler, so decompiler pesudo is not complete
    // change hollow flow to fix try catch issue 20260730
    fn _hollow_encoded_catch_handler_list(&self, data: &[u8], off: usize) -> Vec<Vec<u32>> {
        // encoded_catch_handler_list struct [handler_off, size, encoded_catch_handler]
        let base_off = off;
        let (size, mut c) = read_uleb128_fast(data, off);
        let mut encoded_catch_handler_list: Vec<Vec<u32>> = Vec::new();
        encoded_catch_handler_list.push(vec![size as u32]);
        let mut off = off + c;
        for _ in 0..size {
            let mut encoded_catch_handler = Vec::new();
            encoded_catch_handler.push((off - base_off) as u32);
            let (h_size, c) = read_sleb128(data, off);
            encoded_catch_handler.push(h_size as u32);
            off += c;
            for _ in 0..h_size.unsigned_abs() {
                let (type_idx, c) = read_uleb128_fast(data, off);
                encoded_catch_handler.push(type_idx as u32);
                off += c;
                let (addr, c) = read_uleb128_fast(data, off);
                encoded_catch_handler.push(addr as u32);
                off += c;
            }
            if h_size <= 0 {
                let (catch_all_addr, c) = read_uleb128_fast(data, off);
                encoded_catch_handler.push(catch_all_addr as u32);
                off += c;
            }
            encoded_catch_handler_list.push(encoded_catch_handler);
        }
        encoded_catch_handler_list
    }

    fn _hollow_annotation_set_item(&mut self, off: usize) {
        if off == 0 || self.annotation_sets.contains_key(&(off as u32)) {
            return;
        }
        let data = self._raw_cache;
        let size = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        let mut items = Vec::new();
        let mut p = off + 4;
        for _ in 0..size {
            let annotation_off = u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]);
            p += 4;
            items.push(annotation_off);
            if annotation_off != 0 && !self.annotation_items.contains_key(&annotation_off) {
                let parsed = parse_annotation_item(
                    data,
                    annotation_off as usize,
                    &mut self.hlw_strs,
                    &mut self.hlw_types,
                    &mut self.hlw_fields,
                    &mut self.hlw_methods,
                );
                self.annotation_items.insert(annotation_off, parsed);
            }
        }
        self.annotation_sets.insert(off as u32, AnnotationSet { items });
    }

    fn _hollow_annotation_set_ref_list(&mut self, off: usize) {
        if off == 0 || self.annotation_set_refs.contains_key(&(off as u32)) {
            return;
        }
        let data = self._raw_cache;
        let size = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        let mut refs = Vec::new();
        let mut p = off + 4;
        for _ in 0..size {
            let set_off = u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]);
            p += 4;
            refs.push(set_off);
            self._hollow_annotation_set_item(set_off as usize);
        }
        self.annotation_set_refs.insert(off as u32, refs);
    }

    fn _hollow_annotation_directory_item(&mut self, off: usize) {
        if off == 0 {
            return;
        }
        let data = self._raw_cache;
        let class_annotations_off = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        let fields_size = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
        let methods_size = u32::from_le_bytes([data[off+8], data[off+9], data[off+10], data[off+11]]);
        let parameters_size = u32::from_le_bytes([data[off+12], data[off+13], data[off+14], data[off+15]]);
        self._hollow_annotation_set_item(class_annotations_off as usize);

        let mut p = off + 16;
        let mut field_annotations = Vec::new();
        for _ in 0..fields_size {
            let field_idx = u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]);
            let annotations_off = u32::from_le_bytes([data[p+4], data[p+5], data[p+6], data[p+7]]);
            p += 8;
            field_annotations.push((field_idx, annotations_off));
            self.hlw_fields.insert(field_idx);
            self._hollow_annotation_set_item(annotations_off as usize);
        }

        let mut method_annotations = Vec::new();
        for _ in 0..methods_size {
            let method_idx = u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]);
            let annotations_off = u32::from_le_bytes([data[p+4], data[p+5], data[p+6], data[p+7]]);
            p += 8;
            method_annotations.push((method_idx, annotations_off));
            self.hlw_methods.insert(method_idx);
            self._hollow_annotation_set_item(annotations_off as usize);
        }

        let mut parameter_annotations = Vec::new();
        for _ in 0..parameters_size {
            let method_idx = u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]]);
            let annotations_off = u32::from_le_bytes([data[p+4], data[p+5], data[p+6], data[p+7]]);
            p += 8;
            parameter_annotations.push((method_idx, annotations_off));
            self.hlw_methods.insert(method_idx);
            self._hollow_annotation_set_ref_list(annotations_off as usize);
        }

        self.annotation_directory = Some(AnnotationDirectory {
            class_annotations_off,
            field_annotations,
            method_annotations,
            parameter_annotations,
        });
    }

    pub fn hollow(&mut self) {
        let t_start = if self.debug { Some(Instant::now()) } else { None };

        // WAIT A FUKING MINITE, I should write must of the parse logic by myself
        // I tell LLM to optimize debug info parser, LLM just rewrite whole parse logic and move it to dex_parser.py
        // Almost half of my handwritten logic gone,
        // today when I try to fix try_item issue, I found my code is gone! FUCK! 20260729

        // === CLASS_DEF_ITEM ===
        // https://source.android.com/docs/core/runtime/dex-format#class-def-item
        // clz_def_data = array.array('I', self.clz_raw_byte) -> 8 u32 values from 0x20 bytes
        let clz_def_data: Vec<u32> = self.clz_raw_byte.chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();

        self.clz_def_hlw_types.insert(0, clz_def_data[0]); // class_idx
        self.clz_def_hlw_types.insert(0x4 * 2, clz_def_data[2]); // superclass_idx
        self.clz_def_hlw_strs.insert(0x4 * 4, clz_def_data[4]); // source_file_idx

        let interfaces_off = clz_def_data[3];
        self._hollow_interface_bytes(interfaces_off as usize);
        let t_ifs = if self.debug { Some(Instant::now()) } else { None };

        // === ANNOTATION ===
        let annotations_off = clz_def_data[5];
        self._hollow_annotation_directory_item(annotations_off as usize);

        // === CLASS_DATA ===
        let class_data_off = clz_def_data[6];
        self._hollow_class_data_item_bytes(class_data_off as usize);
        let t_class_data = if self.debug { Some(Instant::now()) } else { None };

        // === STATIC_VALUES ===
        let static_values_off = clz_def_data[7];
        if static_values_off != 0 {
            // which may never be executed, I tried many way to compile a java file contains static fields to dex, never meet static_value_off > 0
            // but LLM still generate this parse, IDK why.. 20260729
            self.static_values_elements = Some(parse_encoded_array(
                self._raw_cache,
                static_values_off as usize,
                &mut self.hlw_strs,
                &mut self.hlw_types,
                &mut self.hlw_fields,
                &mut self.hlw_methods,
            ));
        }
        let t_static = if self.debug { Some(Instant::now()) } else { None };

        // === DEBUG_INFO ===
        let method_indices: Vec<u32> = self.code_item_hlws.keys().cloned().collect();
        for method_idx in method_indices {
            let debug_info_off = self.code_item_metadata_hlws[&method_idx].0;
            if debug_info_off != 0 {
                let debug_item = parse_debug_info(
                    self._raw_cache,
                    debug_info_off as usize,
                    &mut self.hlw_strs,
                    &mut self.hlw_types,
                );
                self.debug_info_items.insert(method_idx, debug_item);
            }
        }

        if self.debug {
            let t_debug = Instant::now();
            let t_start = t_start.unwrap();
            let t_ifs = t_ifs.unwrap();
            let t_class_data = t_class_data.unwrap();
            let t_static = t_static.unwrap();
            println!("[DexHollower Profiler]");
            println!("  Interfaces:  {:.2} us", (t_ifs - t_start).as_secs_f64() * 1000000.0);
            println!("  Class Data:  {:.2} us", (t_class_data - t_ifs).as_secs_f64() * 1000000.0);
            println!("  Static Vals: {:.2} us", (t_static - t_class_data).as_secs_f64() * 1000000.0);
            println!("  Debug Info:  {:.2} us", (t_debug - t_static).as_secs_f64() * 1000000.0);
            println!("  Total:       {:.2} us", (t_debug - t_start).as_secs_f64() * 1000000.0);
        }
    }
}