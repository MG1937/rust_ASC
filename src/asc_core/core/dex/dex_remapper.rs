use std::collections::HashMap;
use std::collections::HashSet;
use crate::asc_core::utils::tinydex::DEX;
use crate::asc_core::utils::tinydex::Type;
use crate::asc_core::utils::tinydex::TypeTypes;
use crate::asc_core::utils::tinydex::PrimitiveTypes;
use crate::asc_core::utils::tinydex::TypeValue;
use crate::asc_core::utils::tinydex::DexClass;
use crate::asc_core::utils::dex_parser::IndexMapper;

// Auth: MG1937

pub struct DexOperator<'a> {
    // due to lief bugs... need to operate raw bytes in DEX ;(
    pub dex: &'a DEX,
    pub _raw_cache: &'a [u8],
    pub type_ids_off: u32,
    pub string_ids_off: u32,
    pub method_ids_off: u32,
    pub field_ids_off: u32,
    pub proto_ids_off: u32,
}

impl<'a> DexOperator<'a> {
    pub fn new(dex: &'a DEX, dex_buffer: &'a [u8]) -> Self {
        DexOperator {
            dex,
            _raw_cache: dex_buffer,
            type_ids_off: dex.header.types.0,
            string_ids_off: dex.header.strings.0,
            method_ids_off: dex.header.methods.0,
            field_ids_off: dex.header.fields.0,
            proto_ids_off: dex.header.prototypes.0,
        }
    }

    pub fn get_type_descidx(&self, type_idx: u32) -> u32 {
        // lief has bugs!!!!!! so we need this
        // https://source.android.com/docs/core/runtime/dex-format#type-codes
        let offset = (self.type_ids_off + type_idx * 0x4) as usize; // type_id_item size == 4
        u32::from_le_bytes([self._raw_cache[offset], self._raw_cache[offset+1], self._raw_cache[offset+2], self._raw_cache[offset+3]])
    }

    pub fn get_proto_shortidx(&self, proto_idx: u32) -> u32 {
        // lief cant access shortidx...
        let offset = (self.proto_ids_off + proto_idx * 0xC) as usize;
        u32::from_le_bytes([self._raw_cache[offset], self._raw_cache[offset+1], self._raw_cache[offset+2], self._raw_cache[offset+3]])
    }

    pub fn get_proto_rettypeidx(&self, proto_idx: u32) -> u32 {
        // lief cant access shortidx...
        let offset = (self.proto_ids_off + proto_idx * 0xC + 4) as usize; // uint == 4
        u32::from_le_bytes([self._raw_cache[offset], self._raw_cache[offset+1], self._raw_cache[offset+2], self._raw_cache[offset+3]])
    }

    pub fn get_method_proto_idx(&self, method_idx: u32) -> u32 {
        // https://source.android.com/docs/core/runtime/dex-format#method-id-item
        let offset = (self.method_ids_off + method_idx * 0x8 + 2) as usize; // ushort == 2
        u16::from_le_bytes([self._raw_cache[offset], self._raw_cache[offset+1]]) as u32
    }
}

pub struct DexIndexMapper<'a> {
    // indexhandler mapper
    pub mapper: HashMap<String, HashMap<u32, u32>>,
    pub dex: &'a DEX,
    pub origin_strings: Vec<String>,
    // Cache dex operator methods for performance
    pub dex_operator: DexOperator<'a>,

    pub str_restruct: Vec<String>, // ["str", ...]
    pub str_restruct_pos: u32,
    pub str_restruct_idx: HashMap<String, u32>, // {"str":str_idx, ...}

    pub type_restruct: Vec<u32>, // [type.descriptor_idx, ...]
    pub type_restruct_pos: u32,
    pub type_restruct_idx: HashMap<(i64, i64), u32>, // {origin_idx or desc_idx:new_idx, ...}

    pub proto_restruct: Vec<Vec<u32>>, // [[shortidx, rettypeidx, paramsize, paramtype, ...], ...]
    pub proto_restruct_pos: u32,
    pub proto_restruct_idx: HashMap<u32, u32>, // {origin_idx:new_idx, ...}

    pub field_restruct: Vec<Vec<u32>>, // [[clz_typeidx, type_typeidx, name_stridx], ...]
    pub field_restruct_pos: u32,
    pub field_restruct_idx: HashMap<u32, u32>, // {origin_idx:new_idx, ...}

    pub method_restruct: Vec<Vec<u32>>, // [[clz_typeidx, proto_typeidx, name_stridx], ...]
    pub method_restruct_pos: u32,
    pub method_restruct_idx: HashMap<u32, u32>, // {origin_idx:newidx, ...}

    // Data set by set_class
    pub class_obj_idx: u32,
    pub methods_obj: Vec<u32>,
    pub fields_obj: Vec<u32>,

    // Internal data
    pub stridx_data_types: HashMap<u32, u32>,
    pub typeidx_data_types: HashMap<u32, u32>,
}

impl<'a> DexIndexMapper<'a> {
    pub fn new(mapper: HashMap<String, HashMap<u32, u32>>, dex: &'a DEX, dex_buffer: &'a [u8]) -> Self {
        let origin_strings = (0..dex.header.strings.1 as usize)
            .map(|i| dex.get_string(i).value.clone())
            .collect();
        let dex_operator = DexOperator::new(dex, dex_buffer);
        DexIndexMapper {
            mapper,
            dex,
            origin_strings,
            dex_operator,
            str_restruct: Vec::new(),
            str_restruct_pos: 0,
            str_restruct_idx: HashMap::new(),
            type_restruct: Vec::new(),
            type_restruct_pos: 0,
            type_restruct_idx: HashMap::new(),
            proto_restruct: Vec::new(),
            proto_restruct_pos: 0,
            proto_restruct_idx: HashMap::new(),
            field_restruct: Vec::new(),
            field_restruct_pos: 0,
            field_restruct_idx: HashMap::new(),
            method_restruct: Vec::new(),
            method_restruct_pos: 0,
            method_restruct_idx: HashMap::new(),
            class_obj_idx: 0,
            methods_obj: Vec::new(),
            fields_obj: Vec::new(),
            stridx_data_types: HashMap::new(),
            typeidx_data_types: HashMap::new(),
        }
    }

    pub fn set_class(&mut self, clz: &mut DexClass) {
        self.class_obj_idx = clz.index;
        self.methods_obj = clz.methods();
        self.fields_obj = clz.fields();
    }

    /// Convert to the simple IndexMapper used by dex_parser rebuild functions
    pub fn to_index_mapper(&self) -> IndexMapper {
        let mut type_restruct_idx = HashMap::new();
        for (&(k1, _k2), &v) in &self.type_restruct_idx {
            if k1 >= 0 {
                type_restruct_idx.insert(k1 as u32, v);
            }
        }
        IndexMapper {
            str_restruct_idx: self.str_restruct_idx.clone(),
            type_restruct_idx,
            field_restruct_idx: self.field_restruct_idx.clone(),
            method_restruct_idx: self.method_restruct_idx.clone(),
            origin_strings: self.origin_strings.clone(),
        }
    }

    fn _fill_data_types(&mut self) {
        // fill data types may not necessary, but all dex need these base types... hh
        self.stridx_data_types = HashMap::new();
        self.typeidx_data_types = HashMap::new();

        let primitives: Vec<(u32, &str)> = vec![
            (PrimitiveTypes::VOID_T, "V"),
            (PrimitiveTypes::BOOLEAN, "Z"),
            (PrimitiveTypes::BYTE, "B"),
            (PrimitiveTypes::SHORT, "S"),
            (PrimitiveTypes::CHAR, "C"),
            (PrimitiveTypes::INT, "I"),
            (PrimitiveTypes::LONG, "J"),
            (PrimitiveTypes::FLOAT, "F"),
            (PrimitiveTypes::DOUBLE, "D"),
        ];

        for (prim_type, char_val) in primitives {
            let str_idx = self._add_str_restruct(char_val.to_string());
            self.stridx_data_types.insert(prim_type, str_idx);
            // We don't have an origin_idx for these primitives necessarily,
            // but we can use the string's new index as a descriptor
            let type_idx = self._add_type_restruct(str_idx, None);
            self.typeidx_data_types.insert(prim_type, type_idx);
        }
    }

    fn _add_str_restruct(&mut self, string: String) -> u32 {
        // return mapped string idx
        if let Some(&idx) = self.str_restruct_idx.get(&string) {
            return idx;
        }
        let idx = self.str_restruct_pos;
        self.str_restruct.push(string.clone());
        self.str_restruct_idx.insert(string, idx);
        self.str_restruct_pos += 1;
        idx
    }

    fn _add_type_restruct(&mut self, desc_idx: u32, origin_idx: Option<u32>) -> u32 {
        // return mapped type idx
        let key = match origin_idx {
            Some(idx) => (idx as i64, -1i64),
            None => (-1i64, desc_idx as i64),
        };
        if let Some(&idx) = self.type_restruct_idx.get(&key) {
            return idx;
        }
        let idx = self.type_restruct_pos;
        self.type_restruct.push(desc_idx);
        self.type_restruct_idx.insert(key, idx);
        self.type_restruct_pos += 1;
        idx
    }

    fn _add_proto_restruct(&mut self, prototype: Vec<u32>, origin_idx: u32) -> u32 {
        // return mapped proto idx
        if let Some(&idx) = self.proto_restruct_idx.get(&origin_idx) {
            return idx;
        }
        let idx = self.proto_restruct_pos;
        self.proto_restruct.push(prototype);
        self.proto_restruct_idx.insert(origin_idx, idx);
        self.proto_restruct_pos += 1;
        idx
    }

    fn _add_field_restruct(&mut self, field: Vec<u32>, origin_idx: u32) -> u32 {
        // return mapped field idx
        if let Some(&idx) = self.field_restruct_idx.get(&origin_idx) {
            return idx;
        }
        let idx = self.field_restruct_pos;
        self.field_restruct.push(field);
        self.field_restruct_idx.insert(origin_idx, idx);
        self.field_restruct_pos += 1;
        idx
    }

    fn _add_method_restruct(&mut self, method: Vec<u32>, origin_idx: u32) -> u32 {
        // return mapped method idx
        if let Some(&idx) = self.method_restruct_idx.get(&origin_idx) {
            return idx;
        }
        let idx = self.method_restruct_pos;
        self.method_restruct.push(method);
        self.method_restruct_idx.insert(origin_idx, idx);
        self.method_restruct_pos += 1;
        idx
    }

    fn _append_origin_type(&mut self, origin_type_idx: u32) -> u32 {
        // assume the type never been added
        // return new_typeidx
        let origin_desc_idx = self.dex_operator.get_type_descidx(origin_type_idx);
        let string = self.origin_strings[origin_desc_idx as usize].clone();
        let new_desc_idx = self._add_str_restruct(string);
        self._add_type_restruct(new_desc_idx, Some(origin_type_idx))
    }

    fn _append_string_to_types(&mut self, string: String) -> u32 {
        // dont care about origin type idx, JUST DROP IT!
        // return new type idx
        let desc_idx = self._add_str_restruct(string);
        self._add_type_restruct(desc_idx, None)
    }

    fn _type_to_descriptor(&self, typ: &mut Type) -> String {
        if typ.type_() == Some(TypeTypes::PRIMITIVE) {
            let m: HashMap<u32, &str> = [
                (PrimitiveTypes::VOID_T, "V"),
                (PrimitiveTypes::BOOLEAN, "Z"),
                (PrimitiveTypes::BYTE, "B"),
                (PrimitiveTypes::SHORT, "S"),
                (PrimitiveTypes::CHAR, "C"),
                (PrimitiveTypes::INT, "I"),
                (PrimitiveTypes::LONG, "J"),
                (PrimitiveTypes::FLOAT, "F"),
                (PrimitiveTypes::DOUBLE, "D"),
            ].iter().cloned().collect();
            if let Some(TypeValue::Primitive(v)) = typ.value() {
                return m[&v].to_string();
            }
            return typ.descriptor.clone();
        } else if typ.type_() == Some(TypeTypes::ARRAY) {
            let dim = typ.dim();
            let underlying = typ.underlying_array_type();
            let mut result = "[".repeat(dim as usize);
            if let Some(mut ut) = underlying {
                result.push_str(&self._type_to_descriptor(&mut ut));
            }
            return result;
        }
        typ.descriptor.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle(
        &mut self,
        hlw_strs: &HashSet<u32>,
        hlw_types: &HashSet<u32>,
        hlw_fields: &HashSet<u32>,
        hlw_methods: &HashSet<u32>,
        clz_def_hlw_types: &HashMap<u32, u32>,
        clz_def_hlw_strs: &HashMap<u32, u32>,
        ifs_list_hlw_types: &[u32],
        code_item_metadata_hlws: &mut HashMap<u32, (u32, Option<Vec<Vec<u32>>>)>,
    ) {
        // === STRING IDX ===
        let str_map = self.mapper.get("STRING").cloned().unwrap_or_default();
        for i in 0..str_map.len() as u32 {
            if let Some(&origin_str_idx) = str_map.get(&i) {
                let string = self.origin_strings[origin_str_idx as usize].clone();
                self._add_str_restruct(string);
            }
        }

        // === TYPE IDX ===
        let type_map = self.mapper.get("TYPE").cloned().unwrap_or_default();
        for i in 0..type_map.len() as u32 {
            if let Some(&origin_type_idx) = type_map.get(&i) {
                self._append_origin_type(origin_type_idx);
            }
        }

        self._fill_data_types();

        // === FIELD IDX ===
        let field_map = self.mapper.get("FIELD").cloned().unwrap_or_default();
        for i in 0..field_map.len() as u32 {
            if let Some(&origin_field_idx) = field_map.get(&i) {
                if self.field_restruct_idx.contains_key(&origin_field_idx) {
                    continue;
                }
                let field_obj = self.dex.get_field(origin_field_idx);
                let fld_clz_string = field_obj.cls().fullname;
                let fld_clz_typeidx = self._append_string_to_types(fld_clz_string);
                let mut fld_type = field_obj.type_();
                let fld_type_string = self._type_to_descriptor(&mut fld_type);
                let fld_type_typeidx = self._append_string_to_types(fld_type_string);
                let fld_name_string = field_obj.name();
                let fld_name_stridx = self._add_str_restruct(fld_name_string);
                let new_field = vec![fld_clz_typeidx, fld_type_typeidx, fld_name_stridx];
                self._add_field_restruct(new_field, field_obj.index);
            }
        }

        // === METHOD IDX ===
        let method_map = self.mapper.get("METHOD").cloned().unwrap_or_default();
        for i in 0..method_map.len() as u32 {
            if let Some(&origin_method_idx) = method_map.get(&i) {
                if self.method_restruct_idx.contains_key(&origin_method_idx) {
                    continue;
                }
                let origin_proto_idx = self.dex_operator.get_method_proto_idx(origin_method_idx);
                let mut short_idx = self.dex_operator.get_proto_shortidx(origin_proto_idx);

                let shorty = self.origin_strings[short_idx as usize].clone();
                short_idx = self._add_str_restruct(shorty);

                let mut rettypeidx = self.dex_operator.get_proto_rettypeidx(origin_proto_idx);
                rettypeidx = self._append_origin_type(rettypeidx);

                let method = self.dex.get_method(origin_method_idx);
                let mut proto = method.prototype();
                let params = proto.parameters_type();

                let param_count = params.len() as u32;
                let mut new_prototype = vec![short_idx, rettypeidx, param_count];

                for param_desc in params {
                    let mut param_type = Type::new(&param_desc);
                    if param_type.type_() == Some(TypeTypes::PRIMITIVE) {
                        if let Some(TypeValue::Primitive(v)) = param_type.value() {
                            new_prototype.push(self.typeidx_data_types[&v]);
                            continue;
                        }
                    }
                    let param_clz_string = self._type_to_descriptor(&mut param_type);
                    let type_idx = self._append_string_to_types(param_clz_string);
                    new_prototype.push(type_idx);
                }
                let new_proto_idx = self._add_proto_restruct(new_prototype, origin_proto_idx);

                let mth_cls_name_string = method.cls().fullname;
                let mth_cls_name_typeidx = self._append_string_to_types(mth_cls_name_string);
                let mth_name_string = method.name();
                let mth_name_stridx = self._add_str_restruct(mth_name_string);
                let new_mth = vec![mth_cls_name_typeidx, new_proto_idx, mth_name_stridx];
                self._add_method_restruct(new_mth, method.index);
            }
        }

        // === CLASS FIELD IDX ===
        let field_idx_keys = self.fields_obj.clone();
        for &field_idx in &field_idx_keys {
            if self.field_restruct_idx.contains_key(&field_idx) {
                continue;
            }
            let field_obj = self.dex.get_field(field_idx);
            let fld_clz_string = field_obj.cls().fullname;
            let fld_clz_typeidx = self._append_string_to_types(fld_clz_string);
            let mut fld_type = field_obj.type_();
            let fld_type_string = self._type_to_descriptor(&mut fld_type);
            let fld_type_typeidx = self._append_string_to_types(fld_type_string);
            let fld_name_string = field_obj.name();
            let fld_name_stridx = self._add_str_restruct(fld_name_string);
            let new_field = vec![fld_clz_typeidx, fld_type_typeidx, fld_name_stridx];
            self._add_field_restruct(new_field, field_obj.index);
        }

        // === CLASS METHOD IDX ===
        let method_idx_keys = self.methods_obj.clone();
        for &method_idx in &method_idx_keys {
            if self.method_restruct_idx.contains_key(&method_idx) {
                continue;
            }
            let origin_proto_idx = self.dex_operator.get_method_proto_idx(method_idx);
            let mut short_idx = self.dex_operator.get_proto_shortidx(origin_proto_idx);

            let shorty = self.origin_strings[short_idx as usize].clone();
            short_idx = self._add_str_restruct(shorty);

            let mut rettypeidx = self.dex_operator.get_proto_rettypeidx(origin_proto_idx);
            rettypeidx = self._append_origin_type(rettypeidx);

            let method = self.dex.get_method(method_idx);
            let mut proto = method.prototype();
            let params = proto.parameters_type();

            let param_count = params.len() as u32;
            let mut new_prototype = vec![short_idx, rettypeidx, param_count];

            for param_desc in params {
                let mut param_type = Type::new(&param_desc);
                if param_type.type_() == Some(TypeTypes::PRIMITIVE) {
                    if let Some(TypeValue::Primitive(v)) = param_type.value() {
                        new_prototype.push(self.typeidx_data_types[&v]);
                        continue;
                    }
                }
                let param_clz_string = self._type_to_descriptor(&mut param_type);
                let type_idx = self._append_string_to_types(param_clz_string);
                new_prototype.push(type_idx);
            }
            let new_proto_idx = self._add_proto_restruct(new_prototype, origin_proto_idx);

            let mth_cls_name_string = method.cls().fullname;
            let mth_cls_name_typeidx = self._append_string_to_types(mth_cls_name_string);
            let mth_name_string = method.name();
            let mth_name_stridx = self._add_str_restruct(mth_name_string);
            let new_mth = vec![mth_cls_name_typeidx, new_proto_idx, mth_name_stridx];
            self._add_method_restruct(new_mth, method.index);
        }

        // === CLASS DEF IDX ===
        // map source file
        if let Some(&src_idx) = clz_def_hlw_strs.get(&0x10) {
            if src_idx != 0xffffffff {
                let src_str = self.origin_strings[src_idx as usize].clone();
                self._add_str_restruct(src_str);
            }
        }
        // map class idx
        if let Some(&clz_idx) = clz_def_hlw_types.get(&0) {
            if clz_idx != 0xffffffff {
                self._append_origin_type(clz_idx);
            }
        }
        // map superclass idx
        if let Some(&super_idx) = clz_def_hlw_types.get(&0x8) {
            if super_idx != 0xffffffff {
                self._append_origin_type(super_idx);
            }
        }
        // map interfaces
        if ifs_list_hlw_types.len() > 0 {
            for i in 1..ifs_list_hlw_types.len() {
                let ifs_idx = ifs_list_hlw_types[i];
                self._append_origin_type(ifs_idx);
            }
        }

        // map generic hollow lists from static values and debug info
        for &s_idx in hlw_strs {
            if s_idx != 0xffffffff && (s_idx as usize) < self.origin_strings.len() {
                self._add_str_restruct(self.origin_strings[s_idx as usize].clone());
            }
        }

        for &t_idx in hlw_types {
            if t_idx != 0xffffffff {
                self._append_origin_type(t_idx);
            }
        }

        for &f_idx in hlw_fields {
            if f_idx != 0xffffffff {
                if !self.field_restruct_idx.contains_key(&f_idx) {
                    let field_obj = self.dex.get_field(f_idx);
                    let fld_clz_string = field_obj.cls().fullname;
                    let fld_clz_typeidx = self._append_string_to_types(fld_clz_string);
                    let mut fld_type = field_obj.type_();
                    let fld_type_string = self._type_to_descriptor(&mut fld_type);
                    let fld_type_typeidx = self._append_string_to_types(fld_type_string);
                    let fld_name_string = field_obj.name();
                    let fld_name_stridx = self._add_str_restruct(fld_name_string);
                    let new_field = vec![fld_clz_typeidx, fld_type_typeidx, fld_name_stridx];
                    self._add_field_restruct(new_field, field_obj.index);
                }
            }
        }

        for &m_idx in hlw_methods {
            if m_idx != 0xffffffff {
                if !self.method_restruct_idx.contains_key(&m_idx) {
                    let origin_proto_idx = self.dex_operator.get_method_proto_idx(m_idx);
                    let mut short_idx = self.dex_operator.get_proto_shortidx(origin_proto_idx);

                    let shorty = self.origin_strings[short_idx as usize].clone();
                    short_idx = self._add_str_restruct(shorty);

                    let mut rettypeidx = self.dex_operator.get_proto_rettypeidx(origin_proto_idx);
                    rettypeidx = self._append_origin_type(rettypeidx);

                    let method = self.dex.get_method(m_idx);
                    let mut proto = method.prototype();
                    let params = proto.parameters_type();

                    let param_count = params.len() as u32;
                    let mut new_prototype = vec![short_idx, rettypeidx, param_count];

                    for param_desc in params {
                        let mut param_type = Type::new(&param_desc);
                        if param_type.type_() == Some(TypeTypes::PRIMITIVE) {
                            if let Some(TypeValue::Primitive(v)) = param_type.value() {
                                new_prototype.push(self.typeidx_data_types[&v]);
                                continue;
                            }
                        }
                        let param_clz_string = self._type_to_descriptor(&mut param_type);
                        let type_idx = self._append_string_to_types(param_clz_string);
                        new_prototype.push(type_idx);
                    }
                    let new_proto_idx = self._add_proto_restruct(new_prototype, origin_proto_idx);

                    let mth_cls_name_string = method.cls().fullname;
                    let mth_cls_name_typeidx = self._append_string_to_types(mth_cls_name_string);
                    let mth_name_string = method.name();
                    let mth_name_stridx = self._add_str_restruct(mth_name_string);
                    let new_mth = vec![mth_cls_name_typeidx, new_proto_idx, mth_name_stridx];
                    self._add_method_restruct(new_mth, method.index);
                }
            }
        }

        // === CODE ITEM TRY_ITEM CATCH HANDLER IDX ===
        for (_method_idx, (_debug_val, catch_handler_list_opt)) in code_item_metadata_hlws.iter_mut() {
            if let Some(catch_handler_list) = catch_handler_list_opt {
                // catch_handler_list: [size, [old_off, h_size, type_idx, addr, ...], ...]
                for i in 1..catch_handler_list.len() {
                    let handler = &mut catch_handler_list[i];
                    let h_size = handler[1] as i32;
                    let mut pos = 2;
                    for _ in 0..h_size.abs() as usize {
                        let old_type_idx = handler[pos];
                        let new_type_idx = self._append_origin_type(old_type_idx);
                        handler[pos] = new_type_idx;
                        pos += 2;
                    }
                }
            }
        }
    }
}