//! Read method definitions without parsing bytecode or decompiling classes.
use crate::asc_core::findrefs::locator::string_locator::StringLocator;
use crate::asc_core::utils::tinydex::_decode_mutf8_fallback;
use std::borrow::Cow;

const METHOD_ID_SIZE: usize = 8;
const SPARSE_NAME_LIMIT: usize = 8;

struct MethodId {
    class: u16,
    prototype: u16,
    name: u32,
}

fn decode_name(raw: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(raw) {
        Ok(name) => Cow::Borrowed(name),
        Err(_) => Cow::Owned(_decode_mutf8_fallback(raw)),
    }
}

struct Table {
    offset: usize,
    count: usize,
    width: usize,
}

impl Table {
    fn read(buf: &[u8], header_offset: usize, width: usize) -> Result<Self, String> {
        let count = u32_at(buf, header_offset)? as usize;
        let offset = u32_at(buf, header_offset + 4)? as usize;
        let size = count.checked_mul(width).ok_or("DEX table size overflow")?;
        let end = offset.checked_add(size).ok_or("DEX table range overflow")?;
        if end > buf.len() {
            return Err("DEX table outside input".to_owned());
        }
        Ok(Self {
            offset,
            count,
            width,
        })
    }

    fn entry(&self, index: usize) -> Result<usize, String> {
        if index >= self.count {
            return Err("DEX table index out of range".to_owned());
        }
        Ok(self.offset + index * self.width)
    }

    fn bytes<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.offset..self.offset + self.count * self.width]
    }
}

fn u16_at(buf: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = buf
        .get(offset..)
        .and_then(|tail| tail.get(..2))
        .ok_or("truncated DEX u16")?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn u32_at(buf: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = buf
        .get(offset..)
        .and_then(|tail| tail.get(..4))
        .ok_or("truncated DEX u32")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn uleb(buf: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let mut value = 0;
    for shift in (0..35).step_by(7) {
        let byte = *buf.get(*cursor).ok_or("truncated DEX uleb128")?;
        *cursor += 1;
        if shift == 28 && byte > 0x0f {
            return Err("DEX uleb128 overflow".to_owned());
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("DEX uleb128 overflow".to_owned())
}

struct Reader<'a> {
    buf: &'a [u8],
    strings: Table,
    types: Table,
    protos: Table,
    methods: Table,
    classes: Table,
    names: Vec<Option<Cow<'a, str>>>,
    prototypes: Vec<Option<Box<str>>>,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Result<Self, String> {
        if buf.len() < 0x70 || &buf[..4] != b"dex\n" || buf[7] != 0 {
            return Err("invalid DEX header".to_owned());
        }
        let strings = Table::read(buf, 0x38, 4)?;
        let types = Table::read(buf, 0x40, 4)?;
        let protos = Table::read(buf, 0x48, 12)?;
        let methods = Table::read(buf, 0x58, METHOD_ID_SIZE)?;
        let classes = Table::read(buf, 0x60, 32)?;
        let names = vec![None; strings.count];
        let prototypes = vec![None; protos.count];
        Ok(Self {
            buf,
            strings,
            types,
            protos,
            methods,
            classes,
            names,
            prototypes,
        })
    }

    fn string(&mut self, index: usize) -> Result<&str, String> {
        let entry = self.strings.entry(index)?;
        if self.names[index].is_none() {
            let offset = u32_at(self.buf, entry)? as usize;
            self.names[index] = Some(decode_name(StringLocator::string_data_bytes(
                self.buf, offset,
            )?));
        }
        Ok(self.names[index].as_deref().unwrap())
    }

    fn type_name(&mut self, index: usize) -> Result<&str, String> {
        let entry = self.types.entry(index)?;
        self.string(u32_at(self.buf, entry)? as usize)
    }

    fn type_bytes(&self, index: usize) -> Result<&[u8], String> {
        let entry = self.types.entry(index)?;
        let string = self.strings.entry(u32_at(self.buf, entry)? as usize)?;
        StringLocator::string_data_bytes(self.buf, u32_at(self.buf, string)? as usize)
    }

    fn method(&self, index: u32) -> Result<MethodId, String> {
        let offset = self.methods.entry(index as usize)?;
        Ok(MethodId {
            class: u16_at(self.buf, offset)?,
            prototype: u16_at(self.buf, offset + 2)?,
            name: u32_at(self.buf, offset + 4)?,
        })
    }

    fn render_method(
        &mut self,
        method: MethodId,
        class: &str,
        filter: Option<&str>,
        text: &mut String,
    ) -> Result<bool, String> {
        let name_index = method.name as usize;
        let proto_index = usize::from(method.prototype);
        let name = self.string(name_index)?;
        if filter.is_some_and(|filter| !name.to_lowercase().contains(filter)) {
            return Ok(false);
        }
        self.ensure_prototype(proto_index)?;
        let name = self.names[name_index].as_deref().unwrap();
        let prototype = self.prototypes[proto_index].as_deref().unwrap();
        text.reserve(class.len() + name.len() + prototype.len() + 3);
        text.push_str(class);
        text.push_str("->");
        text.push_str(name);
        text.push_str(prototype);
        text.push('\n');
        Ok(true)
    }

    fn ensure_prototype(&mut self, index: usize) -> Result<(), String> {
        let entry = self.protos.entry(index)?;
        if self.prototypes[index].is_none() {
            let return_type = u32_at(self.buf, entry + 4)? as usize;
            let parameters = u32_at(self.buf, entry + 8)? as usize;
            let mut descriptor = String::from("(");
            if parameters != 0 {
                let count = u32_at(self.buf, parameters)? as usize;
                let start = parameters
                    .checked_add(4)
                    .ok_or("DEX parameter range overflow")?;
                let size = count.checked_mul(2).ok_or("DEX parameter size overflow")?;
                let end = start
                    .checked_add(size)
                    .ok_or("DEX parameter range overflow")?;
                if end > self.buf.len() {
                    return Err("DEX parameters outside input".to_owned());
                }
                for offset in (start..end).step_by(2) {
                    let type_index = u16_at(self.buf, offset)? as usize;
                    descriptor.push_str(self.type_name(type_index)?);
                }
            }
            descriptor.push(')');
            descriptor.push_str(self.type_name(return_type)?);
            self.prototypes[index] = Some(descriptor.into_boxed_str());
        }
        Ok(())
    }
}

fn matching_methods(reader: &Reader<'_>, query: &str) -> Result<Vec<bool>, String> {
    let table = reader.methods.bytes(reader.buf);
    let names = StringLocator::locate_name_indices(
        reader.buf,
        table
            .chunks_exact(METHOD_ID_SIZE)
            .map(|row| u32::from_le_bytes(row[4..8].try_into().unwrap())),
        query,
    )?;
    let mut methods = vec![false; reader.methods.count];
    if names.len() <= SPARSE_NAME_LIMIT {
        for name in names {
            let needle = name.to_le_bytes();
            let finder = memchr::memmem::Finder::new(&needle);
            let mut offset = 0;
            while let Some(relative) = finder.find(&table[offset..]) {
                let hit = offset + relative;
                if hit % METHOD_ID_SIZE == 4 {
                    methods[hit / METHOD_ID_SIZE] = true;
                    offset = hit + 4;
                } else {
                    // False hits can overlap a real field; advance by one, not four.
                    offset = hit + 1;
                }
            }
        }
    } else {
        let mut names_mask = vec![false; reader.strings.count];
        for name in names {
            names_mask[name as usize] = true;
        }
        for (index, row) in table.chunks_exact(METHOD_ID_SIZE).enumerate() {
            let name = u32::from_le_bytes(row[4..8].try_into().unwrap()) as usize;
            methods[index] = names_mask[name];
        }
    }
    Ok(methods)
}

/// Render defined methods in DEX declaration order.
pub(crate) fn render_dex_methods(
    buf: &[u8],
    class: Option<&str>,
    filter: Option<&str>,
) -> Result<(String, usize), String> {
    let mut reader = Reader::new(buf)?;
    let method_matches = if class.is_none() {
        filter
            .filter(|query| !query.is_empty())
            .map(|query| matching_methods(&reader, query))
            .transpose()?
    } else {
        None
    };
    let name_filter = if method_matches.is_none() {
        filter
    } else {
        None
    };
    let class_bytes = class.map(cesu8::to_java_cesu8);
    let mut text = String::new();
    let mut descriptor = String::new();
    let mut rendered_count = 0;
    for class_index in 0..reader.classes.count {
        let entry = reader.classes.entry(class_index)?;
        let type_index = u32_at(buf, entry)? as usize;
        if let Some(wanted) = &class_bytes
            && reader.type_bytes(type_index)? != wanted.as_ref()
        {
            continue;
        }
        // Reuse one buffer: this runs once per class (hundreds of thousands on
        // a large DEX) and a fresh `String` per iteration is pure allocator churn.
        descriptor.clear();
        descriptor.push_str(reader.type_name(type_index)?);
        let mut cursor = u32_at(buf, entry + 24)? as usize;
        if cursor == 0 {
            continue;
        }
        let static_fields = uleb(buf, &mut cursor)?;
        let instance_fields = uleb(buf, &mut cursor)?;
        let direct_methods = uleb(buf, &mut cursor)?;
        let virtual_methods = uleb(buf, &mut cursor)?;
        for count in [static_fields, instance_fields] {
            for _ in 0..count {
                uleb(buf, &mut cursor)?; // field index delta
                uleb(buf, &mut cursor)?; // access flags
            }
        }
        for count in [direct_methods, virtual_methods] {
            let mut index = 0u32;
            for _ in 0..count {
                index = index
                    .checked_add(uleb(buf, &mut cursor)?)
                    .ok_or("DEX method index overflow")?;
                uleb(buf, &mut cursor)?; // access flags
                uleb(buf, &mut cursor)?; // code offset; do not parse bytecode
                let method = reader.method(index)?;
                if usize::from(method.class) != type_index {
                    return Err("DEX method owner differs from class definition".to_owned());
                }
                if method_matches
                    .as_ref()
                    .is_some_and(|matches| !matches[index as usize])
                {
                    continue;
                }
                if reader.render_method(method, &descriptor, name_filter, &mut text)? {
                    rendered_count += 1;
                }
            }
        }
    }
    Ok((text, rendered_count))
}
