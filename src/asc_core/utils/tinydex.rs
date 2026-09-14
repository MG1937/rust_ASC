use crate::asc_core::utils::leb128::read_uleb128_fast;

struct _STRUCT_I;
impl _STRUCT_I {
    fn unpack_from(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
    }
}

struct _STRUCT_H;
impl _STRUCT_H {
    fn unpack_from(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([buf[off], buf[off+1]])
    }
}

struct _STRUCT_III;
impl _STRUCT_III {
    fn unpack_from(buf: &[u8], off: usize) -> (u32, u32, u32) {
        (
            u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]),
            u32::from_le_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]),
            u32::from_le_bytes([buf[off+8], buf[off+9], buf[off+10], buf[off+11]]),
        )
    }
}

struct _STRUCT_HHI;
impl _STRUCT_HHI {
    fn unpack_from(buf: &[u8], off: usize) -> (u16, u16, u32) {
        (
            u16::from_le_bytes([buf[off], buf[off+1]]),
            u16::from_le_bytes([buf[off+2], buf[off+3]]),
            u32::from_le_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]),
        )
    }
}

struct _STRUCT_HHHHII;
impl _STRUCT_HHHHII {
    fn unpack_from(buf: &[u8], off: usize) -> (u16, u16, u16, u16, u32, u32) {
        (
            u16::from_le_bytes([buf[off], buf[off+1]]),
            u16::from_le_bytes([buf[off+2], buf[off+3]]),
            u16::from_le_bytes([buf[off+4], buf[off+5]]),
            u16::from_le_bytes([buf[off+6], buf[off+7]]),
            u32::from_le_bytes([buf[off+8], buf[off+9], buf[off+10], buf[off+11]]),
            u32::from_le_bytes([buf[off+12], buf[off+13], buf[off+14], buf[off+15]]),
        )
    }
}

pub struct DEXHeader {
    pub strings: (u32, u32), // (off, size)
    pub types: (u32, u32),
    pub prototypes: (u32, u32),
    pub fields: (u32, u32),
    pub methods: (u32, u32),
    pub classes: (u32, u32),
    pub mapoff: u32,
}

impl DEXHeader {
    pub fn new(buf: &[u8]) -> Self {
        DEXHeader {
            strings: (_STRUCT_I::unpack_from(buf, 0x3C), _STRUCT_I::unpack_from(buf, 0x38)),
            types: (_STRUCT_I::unpack_from(buf, 0x44), _STRUCT_I::unpack_from(buf, 0x40)),
            prototypes: (_STRUCT_I::unpack_from(buf, 0x4C), _STRUCT_I::unpack_from(buf, 0x48)),
            fields: (_STRUCT_I::unpack_from(buf, 0x54), _STRUCT_I::unpack_from(buf, 0x50)),
            methods: (_STRUCT_I::unpack_from(buf, 0x5C), _STRUCT_I::unpack_from(buf, 0x58)),
            classes: (_STRUCT_I::unpack_from(buf, 0x64), _STRUCT_I::unpack_from(buf, 0x60)),
            mapoff: _STRUCT_I::unpack_from(buf, 0x34),
        }
    }
}

pub struct PrimitiveTypes;
impl PrimitiveTypes {
    pub const VOID_T: u32 = 0;
    pub const BOOLEAN: u32 = 1;
    pub const BYTE: u32 = 2;
    pub const SHORT: u32 = 3;
    pub const CHAR: u32 = 4;
    pub const INT: u32 = 5;
    pub const LONG: u32 = 6;
    pub const FLOAT: u32 = 7;
    pub const DOUBLE: u32 = 8;
}

pub struct TypeTypes;
impl TypeTypes {
    pub const PRIMITIVE: u32 = 1;
    pub const CLASS: u32 = 2;
    pub const ARRAY: u32 = 3;
}

pub struct Type {
    pub descriptor: String,
    _dim: u32,
    _underlying_array_type: Option<Box<Type>>,
    _value: Option<TypeValue>,
    _type: Option<u32>,
    _parsed: bool,
}

pub enum TypeValue {
    Primitive(u32),
    Class(String),
}

impl Type {
    pub fn new(descriptor: &str) -> Self {
        Type {
            descriptor: descriptor.to_string(),
            _dim: 0,
            _underlying_array_type: None,
            _value: None,
            _type: None,
            _parsed: false,
        }
    }

    fn parse(&mut self) {
        if self._parsed { return; }
        self._parsed = true;
        let desc = self.descriptor.clone();
        let mut d = desc.as_str();
        let mut dim = 0;
        while d.starts_with('[') {
            dim += 1;
            d = &d[1..];
        }
        self._dim = dim;

        if dim > 0 {
            self._type = Some(TypeTypes::ARRAY);
            self._underlying_array_type = Some(Box::new(Type::new(d)));
            return;
        }

        self._type = Some(TypeTypes::CLASS);
        match d {
            "V" => { self._type = Some(TypeTypes::PRIMITIVE); self._value = Some(TypeValue::Primitive(PrimitiveTypes::VOID_T)); }
            "Z" => { self._type = Some(TypeTypes::PRIMITIVE); self._value = Some(TypeValue::Primitive(PrimitiveTypes::BOOLEAN)); }
            "B" => { self._type = Some(TypeTypes::PRIMITIVE); self._value = Some(TypeValue::Primitive(PrimitiveTypes::BYTE)); }
            "S" => { self._type = Some(TypeTypes::PRIMITIVE); self._value = Some(TypeValue::Primitive(PrimitiveTypes::SHORT)); }
            "C" => { self._type = Some(TypeTypes::PRIMITIVE); self._value = Some(TypeValue::Primitive(PrimitiveTypes::CHAR)); }
            "I" => { self._type = Some(TypeTypes::PRIMITIVE); self._value = Some(TypeValue::Primitive(PrimitiveTypes::INT)); }
            "J" => { self._type = Some(TypeTypes::PRIMITIVE); self._value = Some(TypeValue::Primitive(PrimitiveTypes::LONG)); }
            "F" => { self._type = Some(TypeTypes::PRIMITIVE); self._value = Some(TypeValue::Primitive(PrimitiveTypes::FLOAT)); }
            "D" => { self._type = Some(TypeTypes::PRIMITIVE); self._value = Some(TypeValue::Primitive(PrimitiveTypes::DOUBLE)); }
            _ => { self._value = Some(TypeValue::Class(d.to_string())); }
        }
    }

    pub fn dim(&mut self) -> u32 { self.parse(); self._dim }
    pub fn underlying_array_type(&mut self) -> Option<Box<Type>> { self.parse(); self._underlying_array_type.clone() }
    pub fn value(&mut self) -> Option<TypeValue> { self.parse(); self._value.clone() }
    pub fn type_(&mut self) -> Option<u32> { self.parse(); self._type }
}

use std::fmt;
impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.descriptor)
    }
}

pub struct DexString {
    pub value: String,
}

impl DexString {
    pub fn new(value: &str) -> Self { DexString { value: value.to_string() } }
}

impl fmt::Display for DexString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

pub struct DexPrototype {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
    dex: *const DEX,
}

impl DexPrototype {
    pub fn new(dex: &DEX, proto_idx: u32) -> Self {
        let offset = (dex.header.prototypes.0 + proto_idx * 12) as usize;
        let (shorty_idx, return_type_idx, parameters_off) = _STRUCT_III::unpack_from(&dex.buf, offset);
        DexPrototype { shorty_idx, return_type_idx, parameters_off, dex: dex as *const DEX }
    }

    pub fn parameters_type(&self) -> Vec<String> {
        let dex = unsafe { &*self.dex };
        if self.parameters_off == 0 {
            return Vec::new();
        }
        let size = _STRUCT_I::unpack_from(&dex.buf, self.parameters_off as usize) as usize;
        let mut params = Vec::with_capacity(size);
        let mut off = (self.parameters_off + 4) as usize;
        for _ in 0..size {
            let type_idx = _STRUCT_H::unpack_from(&dex.buf, off) as u32;
            off += 2;
            params.push(dex.get_type(type_idx).descriptor.clone());
        }
        params
    }
}

pub struct DexField {
    pub index: u32,
    pub class_idx: u32,
    pub type_idx: u32,
    pub name_idx: u32,
    pub access_flags: u32,
    pub is_static: bool,
    dex: *const DEX,
}

impl DexField {
    pub fn new(dex: &DEX, field_idx: u32) -> Self {
        let offset = (dex.header.fields.0 + field_idx * 8) as usize;
        let (class_idx, type_idx, name_idx) = _STRUCT_HHI::unpack_from(&dex.buf, offset);
        DexField {
            index: field_idx,
            class_idx: class_idx as u32,
            type_idx: type_idx as u32,
            name_idx,
            access_flags: 0,
            is_static: false,
            dex: dex as *const DEX,
        }
    }

    pub fn cls(&self) -> FieldClass {
        let dex = unsafe { &*self.dex };
        FieldClass { fullname: dex.get_type(self.class_idx).descriptor.clone() }
    }

    pub fn type_(&self) -> Type {
        let dex = unsafe { &*self.dex };
        dex.get_type(self.type_idx)
    }

    pub fn name(&self) -> String {
        let dex = unsafe { &*self.dex };
        dex.get_string(self.name_idx as usize).value.clone()
    }
}

pub struct FieldClass {
    pub fullname: String,
}

pub struct DexMethod {
    pub index: u32,
    pub class_idx: u32,
    pub proto_idx: u32,
    pub name_idx: u32,
    pub _code_off: u32,
    pub access_flags: u32,
    pub is_direct: bool,
    pub is_virtual: bool,
    dex: *const DEX,
}

impl DexMethod {
    pub fn new(dex: &DEX, method_idx: u32) -> Self {
        let offset = (dex.header.methods.0 + method_idx * 8) as usize;
        let (class_idx, proto_idx, name_idx) = _STRUCT_HHI::unpack_from(&dex.buf, offset);
        DexMethod {
            index: method_idx,
            class_idx: class_idx as u32,
            proto_idx: proto_idx as u32,
            name_idx,
            _code_off: 0,
            access_flags: 0,
            is_direct: false,
            is_virtual: false,
            dex: dex as *const DEX,
        }
    }

    pub fn cls(&self) -> FieldClass {
        let dex = unsafe { &*self.dex };
        FieldClass { fullname: dex.get_type(self.class_idx).descriptor.clone() }
    }

    pub fn name(&self) -> String {
        let dex = unsafe { &*self.dex };
        dex.get_string(self.name_idx as usize).value.clone()
    }

    pub fn prototype(&self) -> DexPrototype {
        let dex = unsafe { &*self.dex };
        dex.get_prototype(self.proto_idx)
    }

    pub fn code_offset(&self) -> u32 { self._code_off }

    pub fn bytecode(&self) -> Vec<u8> {
        let dex = unsafe { &*self.dex };
        if self._code_off == 0 {
            return Vec::new();
        }
        let off = self._code_off as usize;
        let (registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size) =
            _STRUCT_HHHHII::unpack_from(&dex.buf, off);
        let off = off + 16;
        let insns_bytes = &dex.buf[off..off + insns_size as usize * 2];
        insns_bytes.to_vec()
    }
}

pub struct DexClass {
    pub class_idx: u32,
    pub index: u32,
    pub class_data_off: u32,
    _methods: Vec<usize>,
    _fields: Vec<usize>,
    _parsed: bool,
    dex: *const DEX,
}

impl DexClass {
    pub fn new(dex: &DEX, class_idx: u32, class_def_off: u32, class_index: u32) -> Self {
        let class_data_off = _STRUCT_I::unpack_from(&dex.buf, (class_def_off + 24) as usize);
        DexClass {
            class_idx,
            index: class_index,
            class_data_off,
            _methods: Vec::new(),
            _fields: Vec::new(),
            _parsed: false,
            dex: dex as *const DEX,
        }
    }

    pub fn fullname(&self) -> String {
        let dex = unsafe { &*self.dex };
        dex.get_type(self.class_idx).descriptor.clone()
    }

    fn parse_class_data(&mut self) {
        if self._parsed { return; }
        self._parsed = true;
        if self.class_data_off == 0 { return; }

        let dex = unsafe { &*self.dex };
        let data = &dex.buf;
        let mut pos = self.class_data_off as usize;
        let (static_fields_size, c) = read_uleb128_fast(data, pos); pos += c;
        let (instance_fields_size, c) = read_uleb128_fast(data, pos); pos += c;
        let (direct_methods_size, c) = read_uleb128_fast(data, pos); pos += c;
        let (virtual_methods_size, c) = read_uleb128_fast(data, pos); pos += c;

        let mut field_idx: u32 = 0;
        for _ in 0..static_fields_size {
            let (field_idx_diff, c) = read_uleb128_fast(data, pos); pos += c;
            field_idx += field_idx_diff as u32;
            let (access_flags, c) = read_uleb128_fast(data, pos); pos += c;
            let f = dex.get_field_mut(field_idx);
            f.access_flags = access_flags as u32;
            f.is_static = true;
            self._fields.push(field_idx as usize);
        }

        field_idx = 0;
        for _ in 0..instance_fields_size {
            let (field_idx_diff, c) = read_uleb128_fast(data, pos); pos += c;
            field_idx += field_idx_diff as u32;
            let (access_flags, c) = read_uleb128_fast(data, pos); pos += c;
            let f = dex.get_field_mut(field_idx);
            f.access_flags = access_flags as u32;
            f.is_static = false;
            self._fields.push(field_idx as usize);
        }

        let mut method_idx: u32 = 0;
        for _ in 0..direct_methods_size {
            let (method_idx_diff, c) = read_uleb128_fast(data, pos); pos += c;
            method_idx += method_idx_diff as u32;
            let (access_flags, c) = read_uleb128_fast(data, pos); pos += c;
            let (code_off, c) = read_uleb128_fast(data, pos); pos += c;
            let m = dex.get_method_mut(method_idx);
            m._code_off = code_off as u32;
            m.access_flags = access_flags as u32;
            m.is_direct = true;
            self._methods.push(method_idx as usize);
        }

        method_idx = 0;
        for _ in 0..virtual_methods_size {
            let (method_idx_diff, c) = read_uleb128_fast(data, pos); pos += c;
            method_idx += method_idx_diff as u32;
            let (access_flags, c) = read_uleb128_fast(data, pos); pos += c;
            let (code_off, c) = read_uleb128_fast(data, pos); pos += c;
            let m = dex.get_method_mut(method_idx);
            m._code_off = code_off as u32;
            m.access_flags = access_flags as u32;
            m.is_direct = false;
            m.is_virtual = true;
            self._methods.push(method_idx as usize);
        }
    }

    pub fn methods(&mut self) -> Vec<u32> {
        self.parse_class_data();
        self._methods.iter().map(|&x| x as u32).collect()
    }

    pub fn fields(&mut self) -> Vec<u32> {
        self.parse_class_data();
        self._fields.iter().map(|&x| x as u32).collect()
    }
}

use std::collections::HashMap;
use std::cell::RefCell;

pub struct DEX {
    pub buf: Vec<u8>,
    pub name: String,
    pub header: DEXHeader,
    strings_cache: RefCell<HashMap<usize, DexString>>,
    types_cache: RefCell<HashMap<u32, Type>>,
    prototypes_cache: RefCell<HashMap<u32, DexPrototype>>,
    methods_cache: RefCell<HashMap<u32, DexMethod>>,
    fields_cache: RefCell<HashMap<u32, DexField>>,
    classes_cache: RefCell<Vec<DexClass>>,
    classes_by_name: RefCell<HashMap<String, u32>>,
}

impl DEX {
    pub fn parse(buf: &[u8], name: &str) -> Self {
        DEX {
            buf: buf.to_vec(),
            name: name.to_string(),
            header: DEXHeader::new(buf),
            strings_cache: RefCell::new(HashMap::new()),
            types_cache: RefCell::new(HashMap::new()),
            prototypes_cache: RefCell::new(HashMap::new()),
            methods_cache: RefCell::new(HashMap::new()),
            fields_cache: RefCell::new(HashMap::new()),
            classes_cache: RefCell::new(Vec::new()),
            classes_by_name: RefCell::new(HashMap::new()),
        }
    }

    pub fn get_string(&self, str_idx: usize) -> DexString {
        let mut cache = self.strings_cache.borrow_mut();
        if let Some(s) = cache.get(&str_idx) {
            return s.clone();
        }
        let str_idx_off = self.header.strings.0 as usize;
        let string_off = _STRUCT_I::unpack_from(&self.buf, str_idx_off + str_idx * 4) as usize;
        let (utf16_size, c) = read_uleb128_fast(&self.buf, string_off);
        let data_start = string_off + c;
        let end = data_start + utf16_size as usize;
        let s = String::from_utf8_lossy(&self.buf[data_start..end]).to_string();
        let ds = DexString::new(&s);
        cache.insert(str_idx, ds.clone());
        ds
    }

    pub fn get_type(&self, type_idx: u32) -> Type {
        let mut cache = self.types_cache.borrow_mut();
        if let Some(t) = cache.get(&type_idx) {
            return t.clone();
        }
        let off = self.header.types.0 as usize;
        let type_off = off + type_idx as usize * 4;
        let str_idx = _STRUCT_I::unpack_from(&self.buf, type_off) as usize;
        let t = Type::new(&self.get_string(str_idx).value);
        cache.insert(type_idx, t.clone());
        t
    }

    pub fn get_prototype(&self, proto_idx: u32) -> DexPrototype {
        let mut cache = self.prototypes_cache.borrow_mut();
        if let Some(p) = cache.get(&proto_idx) {
            // can't clone DexPrototype easily due to raw pointer
            // recreate
        }
        let p = DexPrototype::new(self, proto_idx);
        cache.insert(proto_idx, p);
        // return a fresh one - simplified
        DexPrototype::new(self, proto_idx)
    }

    pub fn get_method(&self, method_idx: u32) -> DexMethod {
        let mut cache = self.methods_cache.borrow_mut();
        if let Some(m) = cache.get(&method_idx) {
            // can't clone
        }
        let m = DexMethod::new(self, method_idx);
        cache.insert(method_idx, m);
        DexMethod::new(self, method_idx)
    }

    pub fn get_method_mut<'a>(&'a self, method_idx: u32) -> &'a mut DexMethod {
        if !self.methods_cache.borrow().contains_key(&method_idx) {
            self.methods_cache.borrow_mut().insert(method_idx, DexMethod::new(self, method_idx));
        }
        unsafe {
            let map = self.methods_cache.as_ptr();
            (*map).get_mut(&method_idx).unwrap()
        }
    }

    pub fn get_field(&self, field_idx: u32) -> DexField {
        let mut cache = self.fields_cache.borrow_mut();
        if let Some(f) = cache.get(&field_idx) {
            // can't clone
        }
        let f = DexField::new(self, field_idx);
        cache.insert(field_idx, f);
        DexField::new(self, field_idx)
    }

    pub fn get_field_mut<'a>(&'a self, field_idx: u32) -> &'a mut DexField {
        if !self.fields_cache.borrow().contains_key(&field_idx) {
            self.fields_cache.borrow_mut().insert(field_idx, DexField::new(self, field_idx));
        }
        unsafe {
            let map = self.fields_cache.as_ptr();
            (*map).get_mut(&field_idx).unwrap()
        }
    }

    pub fn classes_len(&self) -> u32 {
        self.header.classes.1
    }

    pub fn get_class_by_idx(&self, class_idx: u32) -> DexClass {
        let mut cache = self.classes_cache.borrow_mut();
        // Ensure vec is populated
        if cache.len() == 0 {
            let off = self.header.classes.0 as usize;
            let size = self.header.classes.1;
            for i in 0..size {
                let class_def_off = off + i as usize * 32;
                let type_idx = _STRUCT_I::unpack_from(&self.buf, class_def_off);
                cache.push(DexClass::new(self, type_idx, class_def_off as u32, i));
            }
        }
        // Return an owned copy - simplified: recreate from raw data
        let off = self.header.classes.0 as usize;
        let class_def_off = off + class_idx as usize * 32;
        let type_idx = _STRUCT_I::unpack_from(&self.buf, class_def_off);
        DexClass::new(self, type_idx, class_def_off as u32, class_idx)
    }

    fn get_uleb128_prefix(&self, lens: usize) -> Vec<u8> {
        if lens < 128 {
            vec![lens as u8]
        } else {
            vec![(lens | 0x80) as u8, (lens >> 7) as u8]
        }
    }

    pub fn get_class(&self, fullname: &str) -> Option<DexClass> {
        // Check cache
        if let Some(idx) = self.classes_by_name.borrow().get(fullname) {
            return Some(self.get_class_by_idx(*idx));
        }

        let off = self.header.classes.0 as usize;
        let size = self.header.classes.1;
        let type_ids_off = self.header.types.0 as usize;
        let type_ids_size = self.header.types.1;

        // Binary search for type_idx
        let mut type_idx: i32 = -1;
        let mut left: i32 = 0;
        let mut right = type_ids_size as i32 - 1;
        while left <= right {
            let mid = (left + right) / 2;
            let desc_idx = _STRUCT_I::unpack_from(&self.buf, type_ids_off + mid as usize * 4) as usize;
            let string = &self.get_string(desc_idx).value;
            if *string == *fullname {
                type_idx = mid;
                break;
            } else if *string < fullname.to_string() {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }

        if type_idx == -1 {
            return None;
        }

        for class_idx in 0..size {
            let class_def_off = off + class_idx as usize * 0x20;
            if _STRUCT_I::unpack_from(&self.buf, class_def_off) != type_idx as u32 {
                continue;
            }
            let clazz = self.get_class_by_idx(class_idx);
            self.classes_by_name.borrow_mut().insert(fullname.to_string(), class_idx);
            return Some(clazz);
        }
        None
    }
}

// Make DexString clonable
impl Clone for DexString {
    fn clone(&self) -> Self {
        DexString { value: self.value.clone() }
    }
}

impl Clone for Type {
    fn clone(&self) -> Self {
        Type {
            descriptor: self.descriptor.clone(),
            _dim: self._dim,
            _underlying_array_type: self._underlying_array_type.clone(),
            _value: self._value.clone(),
            _type: self._type,
            _parsed: self._parsed,
        }
    }
}

impl Clone for TypeValue {
    fn clone(&self) -> Self {
        match self {
            TypeValue::Primitive(v) => TypeValue::Primitive(*v),
            TypeValue::Class(s) => TypeValue::Class(s.clone()),
        }
    }
}

unsafe impl Send for DEX {}
unsafe impl Sync for DEX {}