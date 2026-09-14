// Auth: MG1937

use std::collections::HashSet;

use crate::asc_core::utils::leb128::read_sleb128;
use crate::asc_core::utils::leb128::read_uleb128_fast;
use crate::asc_core::utils::leb128::write_sleb128;
use crate::asc_core::utils::leb128::write_uleb128;

// Types that contain indices:
// 0x17 = STRING
// 0x18 = TYPE
// 0x19 = FIELD
// 0x1A = METHOD
// 0x1B = ENUM (field index)

#[derive(Debug, Clone)]
pub enum EncodedValue {
    Index(u8, u32),                                  // 0x17-0x1B: (value_type, idx)
    Array(u8, Vec<EncodedValue>),                     // 0x1C: elements
    Annotation(u8, u32, Vec<(u32, EncodedValue)>),    // 0x1D: (type_idx, elements)
    NullBool(u8, u8),                                 // 0x1E-0x1F: (value_type, value_arg)
    Primitive(u8, Vec<u8>),                           // others: (value_type, bytes)
}

#[derive(Debug, Clone)]
pub struct EncodedAnnotation {
    pub type_idx: u32,
    pub elements: Vec<(u32, EncodedValue)>,
}

#[derive(Debug, Clone)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct DebugInfo {
    pub line_start: u64,
    pub parameter_names: Vec<u64>,
    pub opcodes: Vec<DebugOpcode>,
}

#[derive(Debug, Clone)]
pub enum DebugOpcode {
    EndSequence,                                          // 0x00
    AdvancePC(u64),                                       // 0x01: addr_diff
    AdvanceLine(i64),                                     // 0x02: line_diff
    StartLocal(u64, u64, u64),                             // 0x03: v_reg, name_idx, type_idx
    StartLocalExtended(u64, u64, u64, u64),                // 0x04: v_reg, name_idx, type_idx, sig_idx
    EndLocal(u64),                                        // 0x05: v_reg
    RestartLocal(u64),                                    // 0x06: v_reg
    SetFile(u64),                                         // 0x09: name_idx
    Other(u8),                                            // others: opcode only
}

pub fn parse_encoded_value(
    data: &[u8],
    pos: usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
    hlw_fields: &mut HashSet<u32>,
    hlw_methods: &mut HashSet<u32>,
) -> (usize, EncodedValue) {
    let start = pos;
    let header = data[pos];
    let mut pos = pos + 1;
    let value_type = header & 0x1f;
    let value_arg = header >> 5;

    if value_type == 0x17 || value_type == 0x18 || value_type == 0x19 || value_type == 0x1A || value_type == 0x1B {
        let size = (value_arg + 1) as usize;
        let mut idx: u32 = 0;
        for i in 0..size {
            idx |= (data[pos + i] as u32) << (i * 8);
        }
        pos += size;

        match value_type {
            0x17 => { hlw_strs.insert(idx); }
            0x18 => { hlw_types.insert(idx); }
            0x19 | 0x1B => { hlw_fields.insert(idx); }
            0x1A => { hlw_methods.insert(idx); }
            _ => {}
        }

        return (pos - start, EncodedValue::Index(value_type, idx));
    }

    if value_type == 0x1C { // ARRAY
        let (size, c) = read_uleb128_fast(data, pos);
        pos += c;
        let mut elements = Vec::new();
        for _ in 0..size {
            let (c, elem) = parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods);
            pos += c;
            elements.push(elem);
        }
        return (pos - start, EncodedValue::Array(value_type, elements));
    }

    if value_type == 0x1D { // ANNOTATION
        let (type_idx, c) = read_uleb128_fast(data, pos);
        pos += c;
        hlw_types.insert(type_idx as u32);
        let (size, c) = read_uleb128_fast(data, pos);
        pos += c;
        let mut elements = Vec::new();
        for _ in 0..size {
            let (name_idx, c) = read_uleb128_fast(data, pos);
            pos += c;
            hlw_strs.insert(name_idx as u32);
            let (c, elem) = parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods);
            pos += c;
            elements.push((name_idx as u32, elem));
        }
        return (pos - start, EncodedValue::Annotation(value_type, type_idx as u32, elements));
    }

    if value_type == 0x1E || value_type == 0x1F { // NULL, BOOLEAN
        return (pos - start, EncodedValue::NullBool(value_type, value_arg));
    }

    // Primitive types (BYTE, SHORT, CHAR, INT, LONG, FLOAT, DOUBLE)
    let size = (value_arg + 1) as usize;
    let val = data[pos..pos + size].to_vec();
    pos += size;
    (pos - start, EncodedValue::Primitive(value_type, val))
}

pub fn parse_encoded_array(
    data: &[u8],
    pos: usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
    hlw_fields: &mut HashSet<u32>,
    hlw_methods: &mut HashSet<u32>,
) -> Vec<EncodedValue> {
    let (size, mut c) = read_uleb128_fast(data, pos);
    let mut pos = pos + c;
    let mut elements = Vec::new();
    for _ in 0..size {
        let (c, elem) = parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods);
        pos += c;
        elements.push(elem);
    }
    elements
}

pub fn parse_encoded_annotation(
    data: &[u8],
    pos: usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
    hlw_fields: &mut HashSet<u32>,
    hlw_methods: &mut HashSet<u32>,
) -> (usize, EncodedAnnotation) {
    let start = pos;
    let (type_idx, mut c) = read_uleb128_fast(data, pos);
    let mut pos = pos + c;
    hlw_types.insert(type_idx as u32);
    let (size, c) = read_uleb128_fast(data, pos);
    pos += c;
    let mut elements = Vec::new();
    for _ in 0..size {
        let (name_idx, c) = read_uleb128_fast(data, pos);
        pos += c;
        hlw_strs.insert(name_idx as u32);
        let (c, elem) = parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods);
        pos += c;
        elements.push((name_idx as u32, elem));
    }
    (pos - start, EncodedAnnotation { type_idx: type_idx as u32, elements })
}

pub fn parse_annotation_item(
    data: &[u8],
    off: usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
    hlw_fields: &mut HashSet<u32>,
    hlw_methods: &mut HashSet<u32>,
) -> AnnotationItem {
    let visibility = data[off];
    let (size, annotation) = parse_encoded_annotation(
        data,
        off + 1,
        hlw_strs,
        hlw_types,
        hlw_fields,
        hlw_methods,
    );
    AnnotationItem {
        visibility,
        annotation,
        size: size + 1,
    }
}

pub struct IndexMapper {
    pub str_restruct_idx: std::collections::HashMap<String, u32>,
    pub type_restruct_idx: std::collections::HashMap<u32, u32>,
    pub field_restruct_idx: std::collections::HashMap<u32, u32>,
    pub method_restruct_idx: std::collections::HashMap<u32, u32>,
    pub origin_strings: Vec<String>,
}

pub fn rebuild_encoded_value(elem: &EncodedValue, im: &IndexMapper) -> Vec<u8> {
    let mut out = Vec::new();

    match elem {
        EncodedValue::Index(value_type, idx) => {
            let new_idx = match value_type {
                0x17 => {
                    let s = if *idx < im.origin_strings.len() as u32 {
                        &im.origin_strings[*idx as usize]
                    } else {
                        ""
                    };
                    *im.str_restruct_idx.get(s).unwrap_or(&0)
                }
                0x18 => *im.type_restruct_idx.get(idx).unwrap_or(&0),
                0x19 | 0x1B => *im.field_restruct_idx.get(idx).unwrap_or(&0),
                0x1A => *im.method_restruct_idx.get(idx).unwrap_or(&0),
                _ => *idx,
            };

            // Calculate size needed
            let mut temp = new_idx;
            let size = if temp > 0xff {
                let mut s = 1;
                while temp > 0xff {
                    temp >>= 8;
                    s += 1;
                }
                s
            } else {
                1
            };

            out.push(((size - 1) << 5) | value_type);
            let mut temp = new_idx;
            for _ in 0..size {
                out.push((temp & 0xff) as u8);
                temp >>= 8;
            }
        }

        EncodedValue::Array(_value_type, elements) => {
            out.push(0x1C); // ARRAY has value_arg = 0
            out.extend(write_uleb128(elements.len() as u64));
            for e in elements {
                out.extend(rebuild_encoded_value(e, im));
            }
        }

        EncodedValue::Annotation(_value_type, type_idx, elements) => {
            out.push(0x1D); // ANNOTATION
            out.extend(write_uleb128(*im.type_restruct_idx.get(type_idx).unwrap_or(&0) as u64));
            out.extend(write_uleb128(elements.len() as u64));
            for (name_idx, e) in elements {
                let s = if *name_idx < im.origin_strings.len() as u32 {
                    &im.origin_strings[*name_idx as usize]
                } else {
                    ""
                };
                out.extend(write_uleb128(*im.str_restruct_idx.get(s).unwrap_or(&0) as u64));
                out.extend(rebuild_encoded_value(e, im));
            }
        }

        EncodedValue::NullBool(value_type, value_arg) => {
            out.push((value_arg << 5) | value_type);
        }

        EncodedValue::Primitive(value_type, val) => {
            out.push((((val.len() - 1) as u8) << 5) | value_type);
            out.extend(val);
        }
    }

    out
}

pub fn rebuild_encoded_array(elements: &[EncodedValue], im: &IndexMapper) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(write_uleb128(elements.len() as u64));
    for e in elements {
        out.extend(rebuild_encoded_value(e, im));
    }
    out
}

pub fn rebuild_encoded_annotation(annotation: &EncodedAnnotation, im: &IndexMapper) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(write_uleb128(*im.type_restruct_idx.get(&annotation.type_idx).unwrap_or(&0) as u64));
    out.extend(write_uleb128(annotation.elements.len() as u64));
    for (name_idx, elem) in &annotation.elements {
        let name = if *name_idx < im.origin_strings.len() as u32 {
            &im.origin_strings[*name_idx as usize]
        } else {
            ""
        };
        out.extend(write_uleb128(*im.str_restruct_idx.get(name).unwrap_or(&0) as u64));
        out.extend(rebuild_encoded_value(elem, im));
    }
    out
}

pub fn rebuild_annotation_item(item: &AnnotationItem, im: &IndexMapper) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(item.visibility);
    out.extend(rebuild_encoded_annotation(&item.annotation, im));
    out
}

pub fn parse_debug_info(
    data: &[u8],
    pos: usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
) -> DebugInfo {
    let mut pos = pos;
    let (line_start, c) = read_uleb128_fast(data, pos);
    pos += c;
    let (parameters_size, c) = read_uleb128_fast(data, pos);
    pos += c;

    let mut parameter_names = Vec::new();
    for _ in 0..parameters_size {
        let (name_idx, c) = read_uleb128_fast(data, pos); // actually uleb128p1
        pos += c;
        parameter_names.push(name_idx);
        if name_idx != 0 {
            hlw_strs.insert((name_idx - 1) as u32);
        }
    }

    let mut opcodes = Vec::new();
    loop {
        let opcode = data[pos];
        pos += 1;
        if opcode == 0x00 {
            // DBG_END_SEQUENCE
            opcodes.push(DebugOpcode::EndSequence);
            break;
        } else if opcode == 0x01 {
            // DBG_ADVANCE_PC
            let (addr_diff, c) = read_uleb128_fast(data, pos);
            pos += c;
            opcodes.push(DebugOpcode::AdvancePC(addr_diff));
        } else if opcode == 0x02 {
            // DBG_ADVANCE_LINE
            let (line_diff, c) = read_sleb128(data, pos);
            pos += c;
            opcodes.push(DebugOpcode::AdvanceLine(line_diff));
        } else if opcode == 0x03 {
            // DBG_START_LOCAL
            let (v_reg, c) = read_uleb128_fast(data, pos);
            pos += c;
            let (name_idx, c) = read_uleb128_fast(data, pos); // uleb128p1
            pos += c;
            let (type_idx, c) = read_uleb128_fast(data, pos); // uleb128p1
            pos += c;
            if name_idx != 0 { hlw_strs.insert((name_idx - 1) as u32); }
            if type_idx != 0 { hlw_types.insert((type_idx - 1) as u32); }
            opcodes.push(DebugOpcode::StartLocal(v_reg, name_idx, type_idx));
        } else if opcode == 0x04 {
            // DBG_START_LOCAL_EXTENDED
            let (v_reg, c) = read_uleb128_fast(data, pos);
            pos += c;
            let (name_idx, c) = read_uleb128_fast(data, pos); // uleb128p1
            pos += c;
            let (type_idx, c) = read_uleb128_fast(data, pos); // uleb128p1
            pos += c;
            let (sig_idx, c) = read_uleb128_fast(data, pos); // uleb128p1
            pos += c;
            if name_idx != 0 { hlw_strs.insert((name_idx - 1) as u32); }
            if type_idx != 0 { hlw_types.insert((type_idx - 1) as u32); }
            if sig_idx != 0 { hlw_strs.insert((sig_idx - 1) as u32); }
            opcodes.push(DebugOpcode::StartLocalExtended(v_reg, name_idx, type_idx, sig_idx));
        } else if opcode == 0x05 {
            // DBG_END_LOCAL
            let (v_reg, c) = read_uleb128_fast(data, pos);
            pos += c;
            opcodes.push(DebugOpcode::EndLocal(v_reg));
        } else if opcode == 0x06 {
            // DBG_RESTART_LOCAL
            let (v_reg, c) = read_uleb128_fast(data, pos);
            pos += c;
            opcodes.push(DebugOpcode::RestartLocal(v_reg));
        } else if opcode == 0x09 {
            // DBG_SET_FILE
            let (name_idx, c) = read_uleb128_fast(data, pos); // uleb128p1
            pos += c;
            if name_idx != 0 { hlw_strs.insert((name_idx - 1) as u32); }
            opcodes.push(DebugOpcode::SetFile(name_idx));
        } else {
            // 0x07, 0x08, and >= 0x0a
            opcodes.push(DebugOpcode::Other(opcode));
        }
    }

    DebugInfo {
        line_start,
        parameter_names,
        opcodes,
    }
}

fn map_debug_name_idx(name_idx: u64, im: &IndexMapper) -> u64 {
    if name_idx == 0 {
        return 0;
    }
    let orig_idx = (name_idx - 1) as usize;
    let s = if orig_idx < im.origin_strings.len() {
        &im.origin_strings[orig_idx]
    } else {
        ""
    };
    (*im.str_restruct_idx.get(s).unwrap_or(&0) + 1) as u64
}

fn map_debug_type_idx(type_idx: u64, im: &IndexMapper) -> u64 {
    if type_idx == 0 {
        return 0;
    }
    let orig_idx = type_idx - 1;
    (*im.type_restruct_idx.get(&(orig_idx as u32)).unwrap_or(&0) + 1) as u64
}

pub fn rebuild_debug_info(info: &DebugInfo, im: &IndexMapper) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(write_uleb128(info.line_start));
    out.extend(write_uleb128(info.parameter_names.len() as u64));
    for name_idx in &info.parameter_names {
        if *name_idx == 0 {
            out.extend(write_uleb128(0));
        } else {
            let orig_idx = (*name_idx - 1) as usize;
            let s = if orig_idx < im.origin_strings.len() {
                &im.origin_strings[orig_idx]
            } else {
                ""
            };
            let new_idx = im.str_restruct_idx.get(s).unwrap_or(&0);
            out.extend(write_uleb128((*new_idx + 1) as u64));
        }
    }

    for op in &info.opcodes {
        match op {
            DebugOpcode::EndSequence => {
                out.push(0x00);
            }
            DebugOpcode::AdvancePC(addr_diff) => {
                out.push(0x01);
                out.extend(write_uleb128(*addr_diff));
            }
            DebugOpcode::AdvanceLine(line_diff) => {
                out.push(0x02);
                out.extend(write_sleb128(*line_diff));
            }
            DebugOpcode::StartLocal(v_reg, name_idx, type_idx) => {
                out.push(0x03);
                out.extend(write_uleb128(*v_reg));
                out.extend(write_uleb128(map_debug_name_idx(*name_idx, im)));
                out.extend(write_uleb128(map_debug_type_idx(*type_idx, im)));
            }
            DebugOpcode::StartLocalExtended(v_reg, name_idx, type_idx, sig_idx) => {
                out.push(0x04);
                out.extend(write_uleb128(*v_reg));
                out.extend(write_uleb128(map_debug_name_idx(*name_idx, im)));
                out.extend(write_uleb128(map_debug_type_idx(*type_idx, im)));
                out.extend(write_uleb128(map_debug_name_idx(*sig_idx, im)));
            }
            DebugOpcode::EndLocal(v_reg) => {
                out.push(0x05);
                out.extend(write_uleb128(*v_reg));
            }
            DebugOpcode::RestartLocal(v_reg) => {
                out.push(0x06);
                out.extend(write_uleb128(*v_reg));
            }
            DebugOpcode::SetFile(name_idx) => {
                out.push(0x09);
                out.extend(write_uleb128(map_debug_name_idx(*name_idx, im)));
            }
            DebugOpcode::Other(opcode) => {
                out.push(*opcode);
            }
        }
    }

    out
}