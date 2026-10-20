use crate::asc_core::utils::leb128::read_uleb128_fast;
use crate::asc_core::utils::structs::{_STRUCT_H, _STRUCT_HHI, _STRUCT_HHHHII, _STRUCT_I, _STRUCT_III};
use cesu8::from_java_cesu8;
use memchr::memchr;
use std::cell::{RefCell, RefMut};
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

pub fn _decode_mutf8_fallback(raw: &[u8]) -> String {
    match from_java_cesu8(raw) {
        Ok(value) => value.into_owned(),
        Err(_) => {
            let mut normalized = Vec::with_capacity(raw.len());
            let mut bytes = raw.iter().copied().peekable();
            while let Some(byte) = bytes.next() {
                normalized.push(if byte == 0xc0 && bytes.next_if_eq(&0x80).is_some() {
                    0
                } else {
                    byte
                });
            }
            String::from_utf8_lossy(&normalized).into_owned()
        }
    }
}

#[derive(Clone, Copy)]
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
        if self._parsed {
            return;
        }
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
            "V" => {
                self._type = Some(TypeTypes::PRIMITIVE);
                self._value = Some(TypeValue::Primitive(PrimitiveTypes::VOID_T));
            }
            "Z" => {
                self._type = Some(TypeTypes::PRIMITIVE);
                self._value = Some(TypeValue::Primitive(PrimitiveTypes::BOOLEAN));
            }
            "B" => {
                self._type = Some(TypeTypes::PRIMITIVE);
                self._value = Some(TypeValue::Primitive(PrimitiveTypes::BYTE));
            }
            "S" => {
                self._type = Some(TypeTypes::PRIMITIVE);
                self._value = Some(TypeValue::Primitive(PrimitiveTypes::SHORT));
            }
            "C" => {
                self._type = Some(TypeTypes::PRIMITIVE);
                self._value = Some(TypeValue::Primitive(PrimitiveTypes::CHAR));
            }
            "I" => {
                self._type = Some(TypeTypes::PRIMITIVE);
                self._value = Some(TypeValue::Primitive(PrimitiveTypes::INT));
            }
            "J" => {
                self._type = Some(TypeTypes::PRIMITIVE);
                self._value = Some(TypeValue::Primitive(PrimitiveTypes::LONG));
            }
            "F" => {
                self._type = Some(TypeTypes::PRIMITIVE);
                self._value = Some(TypeValue::Primitive(PrimitiveTypes::FLOAT));
            }
            "D" => {
                self._type = Some(TypeTypes::PRIMITIVE);
                self._value = Some(TypeValue::Primitive(PrimitiveTypes::DOUBLE));
            }
            _ => {
                self._value = Some(TypeValue::Class(d.to_string()));
            }
        }
    }

    pub fn dim(&mut self) -> u32 {
        self.parse();
        self._dim
    }

    pub fn underlying_array_type(&mut self) -> Option<Box<Type>> {
        self.parse();
        self._underlying_array_type.clone()
    }

    pub fn value(&mut self) -> Option<TypeValue> {
        self.parse();
        self._value.clone()
    }

    pub fn type_(&mut self) -> Option<u32> {
        self.parse();
        self._type
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.descriptor)
    }
}

pub struct DexString {
    pub value: String,
}

impl DexString {
    pub fn new(value: &str) -> Self {
        DexString {
            value: value.to_string(),
        }
    }
}

impl fmt::Display for DexString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

struct DexContext {
    buf: Rc<Vec<u8>>,
    header: DEXHeader,
    strings_cache: RefCell<HashMap<usize, DexString>>,
    types_cache: RefCell<HashMap<u32, Type>>,
    prototypes_cache: RefCell<HashMap<u32, DexPrototype>>,
    methods_cache: RefCell<HashMap<u32, DexMethod>>,
    fields_cache: RefCell<HashMap<u32, DexField>>,
    classes_cache: RefCell<Vec<DexClass>>,
    classes_by_name: RefCell<HashMap<String, u32>>,
}

#[derive(Clone)]
pub struct DexPrototype {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
    context: Rc<DexContext>,
}

impl DexPrototype {
    pub fn new(dex: &DEX, proto_idx: u32) -> Self {
        Self::new_with_context(&dex.context, proto_idx)
    }

    fn new_with_context(context: &Rc<DexContext>, proto_idx: u32) -> Self {
        let offset = (context.header.prototypes.0 + proto_idx * 12) as usize;
        let (shorty_idx, return_type_idx, parameters_off) =
            _STRUCT_III::unpack_from(&context.buf, offset);
        DexPrototype {
            shorty_idx,
            return_type_idx,
            parameters_off,
            context: Rc::clone(context),
        }
    }

    pub fn parameters_type(&self) -> Vec<String> {
        if self.parameters_off == 0 {
            return Vec::new();
        }
        let size = _STRUCT_I::unpack_from(&self.context.buf, self.parameters_off as usize) as usize;
        let mut params = Vec::with_capacity(size);
        let mut off = (self.parameters_off + 4) as usize;
        for _ in 0..size {
            let type_idx = _STRUCT_H::unpack_from(&self.context.buf, off) as u32;
            off += 2;
            params.push(self.context.get_type(type_idx).descriptor);
        }
        params
    }
}

#[derive(Clone)]
pub struct DexField {
    pub index: u32,
    pub class_idx: u32,
    pub type_idx: u32,
    pub name_idx: u32,
    pub access_flags: u32,
    pub is_static: bool,
    context: Rc<DexContext>,
}

impl DexField {
    pub fn new(dex: &DEX, field_idx: u32) -> Self {
        Self::new_with_context(&dex.context, field_idx)
    }

    fn new_with_context(context: &Rc<DexContext>, field_idx: u32) -> Self {
        let offset = (context.header.fields.0 + field_idx * 8) as usize;
        let (class_idx, type_idx, name_idx) = _STRUCT_HHI::unpack_from(&context.buf, offset);
        DexField {
            index: field_idx,
            class_idx: class_idx as u32,
            type_idx: type_idx as u32,
            name_idx,
            access_flags: 0,
            is_static: false,
            context: Rc::clone(context),
        }
    }

    pub fn cls(&self) -> FieldClass {
        FieldClass {
            fullname: self.context.get_type(self.class_idx).descriptor,
        }
    }

    pub fn type_(&self) -> Type {
        self.context.get_type(self.type_idx)
    }

    pub fn name(&self) -> String {
        self.context.get_string(self.name_idx as usize).value
    }
}

pub struct FieldClass {
    pub fullname: String,
}

#[derive(Clone)]
pub struct DexMethod {
    pub index: u32,
    pub class_idx: u32,
    pub proto_idx: u32,
    pub name_idx: u32,
    pub _code_off: u32,
    pub access_flags: u32,
    pub is_direct: bool,
    pub is_virtual: bool,
    context: Rc<DexContext>,
}

impl DexMethod {
    pub fn new(dex: &DEX, method_idx: u32) -> Self {
        Self::new_with_context(&dex.context, method_idx)
    }

    fn new_with_context(context: &Rc<DexContext>, method_idx: u32) -> Self {
        let offset = (context.header.methods.0 + method_idx * 8) as usize;
        let (class_idx, proto_idx, name_idx) = _STRUCT_HHI::unpack_from(&context.buf, offset);
        DexMethod {
            index: method_idx,
            class_idx: class_idx as u32,
            proto_idx: proto_idx as u32,
            name_idx,
            _code_off: 0,
            access_flags: 0,
            is_direct: false,
            is_virtual: false,
            context: Rc::clone(context),
        }
    }

    pub fn cls(&self) -> FieldClass {
        FieldClass {
            fullname: self.context.get_type(self.class_idx).descriptor,
        }
    }

    pub fn name(&self) -> String {
        self.context.get_string(self.name_idx as usize).value
    }

    pub fn prototype(&self) -> DexPrototype {
        DexContext::get_prototype(&self.context, self.proto_idx)
    }

    pub fn code_offset(&self) -> u32 {
        self._code_off
    }

    pub fn bytecode(&self) -> Vec<u8> {
        if self._code_off == 0 {
            return Vec::new();
        }
        let off = self._code_off as usize;
        let (_, _, _, _, _, insns_size) =
            _STRUCT_HHHHII::unpack_from(&self.context.buf, off);
        let off = off + 16;
        let insns_bytes = &self.context.buf[off..off + insns_size as usize * 2];
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
    context: Rc<DexContext>,
}

impl DexClass {
    pub fn new(dex: &DEX, class_idx: u32, class_def_off: u32, class_index: u32) -> Self {
        Self::new_with_context(&dex.context, class_idx, class_def_off, class_index)
    }

    fn new_with_context(
        context: &Rc<DexContext>,
        class_idx: u32,
        class_def_off: u32,
        class_index: u32,
    ) -> Self {
        let class_data_off = _STRUCT_I::unpack_from(&context.buf, (class_def_off + 24) as usize);
        DexClass {
            class_idx,
            index: class_index,
            class_data_off,
            _methods: Vec::new(),
            _fields: Vec::new(),
            _parsed: false,
            context: Rc::clone(context),
        }
    }

    pub fn fullname(&self) -> String {
        self.context.get_type(self.class_idx).descriptor
    }

    fn parse_class_data(&mut self) {
        if self._parsed {
            return;
        }
        self._parsed = true;
        if self.class_data_off == 0 {
            return;
        }

        let data = &self.context.buf;
        let mut pos = self.class_data_off as usize;
        let (static_fields_size, c) = read_uleb128_fast(data, pos);
        pos += c;
        let (instance_fields_size, c) = read_uleb128_fast(data, pos);
        pos += c;
        let (direct_methods_size, c) = read_uleb128_fast(data, pos);
        pos += c;
        let (virtual_methods_size, c) = read_uleb128_fast(data, pos);
        pos += c;

        let mut field_idx: u32 = 0;
        for _ in 0..static_fields_size {
            let (field_idx_diff, c) = read_uleb128_fast(data, pos);
            pos += c;
            field_idx += field_idx_diff as u32;
            let (access_flags, c) = read_uleb128_fast(data, pos);
            pos += c;
            let mut field = DexContext::get_field_mut(&self.context, field_idx);
            field.access_flags = access_flags as u32;
            field.is_static = true;
            self._fields.push(field_idx as usize);
        }

        field_idx = 0;
        for _ in 0..instance_fields_size {
            let (field_idx_diff, c) = read_uleb128_fast(data, pos);
            pos += c;
            field_idx += field_idx_diff as u32;
            let (access_flags, c) = read_uleb128_fast(data, pos);
            pos += c;
            let mut field = DexContext::get_field_mut(&self.context, field_idx);
            field.access_flags = access_flags as u32;
            field.is_static = false;
            self._fields.push(field_idx as usize);
        }

        let mut method_idx: u32 = 0;
        for _ in 0..direct_methods_size {
            let (method_idx_diff, c) = read_uleb128_fast(data, pos);
            pos += c;
            method_idx += method_idx_diff as u32;
            let (access_flags, c) = read_uleb128_fast(data, pos);
            pos += c;
            let (code_off, c) = read_uleb128_fast(data, pos);
            pos += c;
            let mut method = DexContext::get_method_mut(&self.context, method_idx);
            method._code_off = code_off as u32;
            method.access_flags = access_flags as u32;
            method.is_direct = true;
            self._methods.push(method_idx as usize);
        }

        method_idx = 0;
        for _ in 0..virtual_methods_size {
            let (method_idx_diff, c) = read_uleb128_fast(data, pos);
            pos += c;
            method_idx += method_idx_diff as u32;
            let (access_flags, c) = read_uleb128_fast(data, pos);
            pos += c;
            let (code_off, c) = read_uleb128_fast(data, pos);
            pos += c;
            let mut method = DexContext::get_method_mut(&self.context, method_idx);
            method._code_off = code_off as u32;
            method.access_flags = access_flags as u32;
            method.is_direct = false;
            method.is_virtual = true;
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

impl DexContext {
    fn get_string(&self, str_idx: usize) -> DexString {
        let mut cache = self.strings_cache.borrow_mut();
        if let Some(s) = cache.get(&str_idx) {
            return s.clone();
        }
        let str_idx_off = self.header.strings.0 as usize;
        let string_off = _STRUCT_I::unpack_from(&self.buf, str_idx_off + str_idx * 4) as usize;
        let (utf16_size, c) = read_uleb128_fast(&self.buf, string_off);
        let data_start = string_off + c;
        let mut end = data_start
            .checked_add(utf16_size as usize)
            .unwrap_or(usize::MAX);
        // ASCII keeps the old O(1) boundary calculation; MUTF-8 needs its terminator.
        // refer to https://github.com/MG1937/ASC/issues/33
        // 20260923 DEX.get_string slices utf16_size bytes out of a string_data_item, but that field counts UTF-16 code units
        if end >= self.buf.len() || self.buf[end] != 0 {
            end = self
                .buf
                .get(data_start..)
                .and_then(|raw| memchr(0, raw))
                .map(|offset| data_start + offset)
                .expect("unterminated string_data_item");
        }

        let raw = &self.buf[data_start..end];
        let s = match std::str::from_utf8(raw) {
            Ok(s) => s.to_string(),
            Err(_) => _decode_mutf8_fallback(raw),
        };
        let ds = DexString::new(&s);
        cache.insert(str_idx, ds.clone());
        ds
    }

    fn get_type(&self, type_idx: u32) -> Type {
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

    fn get_prototype(context: &Rc<Self>, proto_idx: u32) -> DexPrototype {
        let mut cache = context.prototypes_cache.borrow_mut();
        if let Some(p) = cache.get(&proto_idx) {
            return p.clone();
        }
        let p = DexPrototype::new_with_context(context, proto_idx);
        cache.insert(proto_idx, p.clone());
        p
    }

    fn get_method(context: &Rc<Self>, method_idx: u32) -> DexMethod {
        let mut cache = context.methods_cache.borrow_mut();
        if let Some(m) = cache.get(&method_idx) {
            return m.clone();
        }
        let m = DexMethod::new_with_context(context, method_idx);
        cache.insert(method_idx, m.clone());
        m
    }

    fn get_method_mut(context: &Rc<Self>, method_idx: u32) -> RefMut<'_, DexMethod> {
        if !context.methods_cache.borrow().contains_key(&method_idx) {
            context
                .methods_cache
                .borrow_mut()
                .insert(method_idx, DexMethod::new_with_context(context, method_idx));
        }
        RefMut::map(context.methods_cache.borrow_mut(), |cache| {
            cache.get_mut(&method_idx).unwrap()
        })
    }

    fn get_field(context: &Rc<Self>, field_idx: u32) -> DexField {
        let mut cache = context.fields_cache.borrow_mut();
        if let Some(f) = cache.get(&field_idx) {
            return f.clone();
        }
        let f = DexField::new_with_context(context, field_idx);
        cache.insert(field_idx, f.clone());
        f
    }

    fn get_field_mut(context: &Rc<Self>, field_idx: u32) -> RefMut<'_, DexField> {
        if !context.fields_cache.borrow().contains_key(&field_idx) {
            context
                .fields_cache
                .borrow_mut()
                .insert(field_idx, DexField::new_with_context(context, field_idx));
        }
        RefMut::map(context.fields_cache.borrow_mut(), |cache| {
            cache.get_mut(&field_idx).unwrap()
        })
    }

    fn get_class_by_idx(context: &Rc<Self>, class_idx: u32) -> DexClass {
        let mut cache = context.classes_cache.borrow_mut();
        if cache.is_empty() {
            let off = context.header.classes.0 as usize;
            let size = context.header.classes.1;
            for i in 0..size {
                let class_def_off = off + i as usize * 32;
                let type_idx = _STRUCT_I::unpack_from(&context.buf, class_def_off);
                cache.push(DexClass::new_with_context(
                    context,
                    type_idx,
                    class_def_off as u32,
                    i,
                ));
            }
        }
        let off = context.header.classes.0 as usize;
        let class_def_off = off + class_idx as usize * 32;
        let type_idx = _STRUCT_I::unpack_from(&context.buf, class_def_off);
        DexClass::new_with_context(context, type_idx, class_def_off as u32, class_idx)
    }

    fn get_class(context: &Rc<Self>, fullname: &str) -> Option<DexClass> {
        if let Some(idx) = context.classes_by_name.borrow().get(fullname) {
            return Some(Self::get_class_by_idx(context, *idx));
        }

        let off = context.header.classes.0 as usize;
        let size = context.header.classes.1;
        let type_ids_off = context.header.types.0 as usize;
        let type_ids_size = context.header.types.1;

        let mut type_idx: i32 = -1;
        let mut left: i32 = 0;
        let mut right: i32 = type_ids_size as i32 - 1;
        while left <= right {
            let mid = (left + right) / 2;
            let desc_idx =
                _STRUCT_I::unpack_from(&context.buf, type_ids_off + mid as usize * 4) as usize;
            let string = &context.get_string(desc_idx).value;
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
            // DEX sorts by UTF-16 code units, while Rust compares Unicode scalar values.
            for mid in 0..type_ids_size {
                let desc_idx =
                    _STRUCT_I::unpack_from(&context.buf, type_ids_off + mid as usize * 4) as usize;
                if context.get_string(desc_idx).value == fullname {
                    type_idx = mid as i32;
                    break;
                }
            }
        }

        if type_idx == -1 {
            return None;
        }

        for class_idx in 0..size {
            let class_def_off = off + class_idx as usize * 0x20;
            if _STRUCT_I::unpack_from(&context.buf, class_def_off) != type_idx as u32 {
                continue;
            }
            let clazz = Self::get_class_by_idx(context, class_idx);
            context
                .classes_by_name
                .borrow_mut()
                .insert(fullname.to_string(), class_idx);
            return Some(clazz);
        }
        None
    }
}

pub struct DEX {
    pub buf: Rc<Vec<u8>>,
    pub name: String,
    pub header: DEXHeader,
    context: Rc<DexContext>,
}

impl DEX {
    pub fn parse(buf: &[u8], name: &str) -> Self {
        Self::from_vec(buf.to_vec(), name)
    }

    /// Recover the backing buffer so a worker can reuse its pages for the next
    /// DEX instead of allocating fresh multi-MB memory per entry.
    pub fn into_vec(mut self) -> Vec<u8> {
        let buf = std::mem::replace(&mut self.buf, std::rc::Rc::new(Vec::new()));
        // Dropping the DEX releases the context's second reference, leaving
        // `buf` uniquely owned in the common case (no copy).
        drop(self);
        match std::rc::Rc::try_unwrap(buf) {
            Ok(vec) => vec,
            Err(shared) => shared.as_ref().clone(),
        }
    }

    pub fn from_vec(buf: Vec<u8>, name: &str) -> Self {
        let buf = Rc::new(buf);
        let header = DEXHeader::new(&buf);
        let context = Rc::new(DexContext {
            buf: Rc::clone(&buf),
            header,
            strings_cache: RefCell::new(HashMap::new()),
            types_cache: RefCell::new(HashMap::new()),
            prototypes_cache: RefCell::new(HashMap::new()),
            methods_cache: RefCell::new(HashMap::new()),
            fields_cache: RefCell::new(HashMap::new()),
            classes_cache: RefCell::new(Vec::new()),
            classes_by_name: RefCell::new(HashMap::new()),
        });
        DEX {
            buf,
            name: name.to_string(),
            header,
            context,
        }
    }

    pub fn get_string(&self, str_idx: usize) -> DexString {
        self.context.get_string(str_idx)
    }

    pub fn get_type(&self, type_idx: u32) -> Type {
        self.context.get_type(type_idx)
    }

    pub fn get_prototype(&self, proto_idx: u32) -> DexPrototype {
        DexContext::get_prototype(&self.context, proto_idx)
    }

    pub fn get_method(&self, method_idx: u32) -> DexMethod {
        DexContext::get_method(&self.context, method_idx)
    }

    pub fn get_method_mut(&self, method_idx: u32) -> RefMut<'_, DexMethod> {
        DexContext::get_method_mut(&self.context, method_idx)
    }

    pub fn get_field(&self, field_idx: u32) -> DexField {
        DexContext::get_field(&self.context, field_idx)
    }

    pub fn get_field_mut(&self, field_idx: u32) -> RefMut<'_, DexField> {
        DexContext::get_field_mut(&self.context, field_idx)
    }

    pub fn classes_len(&self) -> u32 {
        self.header.classes.1
    }

    pub fn get_class_by_idx(&self, class_idx: u32) -> DexClass {
        DexContext::get_class_by_idx(&self.context, class_idx)
    }

    pub fn get_class(&self, fullname: &str) -> Option<DexClass> {
        DexContext::get_class(&self.context, fullname)
    }
}

impl Drop for DEX {
    fn drop(&mut self) {
        self.context.prototypes_cache.borrow_mut().clear();
        self.context.methods_cache.borrow_mut().clear();
        self.context.fields_cache.borrow_mut().clear();
        self.context.classes_cache.borrow_mut().clear();
    }
}

impl Clone for DexString {
    fn clone(&self) -> Self {
        DexString {
            value: self.value.clone(),
        }
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
