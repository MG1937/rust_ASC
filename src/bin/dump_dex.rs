use std::env;
use std::fs;
use std::io::Read;

use rust_ASC::asc_core::core::dex::dex_manager::DexManager;

// === Minimal DEX parser for dump ===

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off+1]])
}

#[derive(Debug)]
struct DexHeader {
    magic: [u8; 8],
    checksum: u32,
    signature: [u8; 20],
    file_size: u32,
    header_size: u32,
    endian_tag: u32,
    link_size: u32,
    link_off: u32,
    map_off: u32,
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    proto_ids_size: u32,
    proto_ids_off: u32,
    field_ids_size: u32,
    field_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
    class_defs_off: u32,
    data_size: u32,
    data_off: u32,
}

fn parse_header(buf: &[u8]) -> DexHeader {
    assert!(buf.len() >= 0x70, "File too small for header");
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&buf[0..8]);
    DexHeader {
        magic,
        checksum: read_u32(buf, 8),
        signature: {
            let mut sig = [0u8; 20];
            sig.copy_from_slice(&buf[12..32]);
            sig
        },
        file_size: read_u32(buf, 32),
        header_size: read_u32(buf, 36),
        endian_tag: read_u32(buf, 40),
        link_size: read_u32(buf, 44),
        link_off: read_u32(buf, 48),
        map_off: read_u32(buf, 52),
        string_ids_size: read_u32(buf, 56),
        string_ids_off: read_u32(buf, 60),
        type_ids_size: read_u32(buf, 64),
        type_ids_off: read_u32(buf, 68),
        proto_ids_size: read_u32(buf, 72),
        proto_ids_off: read_u32(buf, 76),
        field_ids_size: read_u32(buf, 80),
        field_ids_off: read_u32(buf, 84),
        method_ids_size: read_u32(buf, 88),
        method_ids_off: read_u32(buf, 92),
        class_defs_size: read_u32(buf, 96),
        class_defs_off: read_u32(buf, 100),
        data_size: read_u32(buf, 104),
        data_off: read_u32(buf, 108),
    }
}

fn dump_header(buf: &[u8]) {
    let hdr = parse_header(buf);
    println!("=== DEX Header ===");
    println!("  magic:           {:02X?}", hdr.magic);
    println!("  file_size:       {}", hdr.file_size);
    println!("  header_size:     {} (0x{:X})", hdr.header_size, hdr.header_size);
    println!("  endian_tag:      0x{:08X}", hdr.endian_tag);
    println!("  map_off:         {} (0x{:X})", hdr.map_off, hdr.map_off);
    println!("  string_ids:      size={}, off={} (0x{:X})", hdr.string_ids_size, hdr.string_ids_off, hdr.string_ids_off);
    println!("  type_ids:        size={}, off={} (0x{:X})", hdr.type_ids_size, hdr.type_ids_off, hdr.type_ids_off);
    println!("  proto_ids:       size={}, off={} (0x{:X})", hdr.proto_ids_size, hdr.proto_ids_off, hdr.proto_ids_off);
    println!("  field_ids:       size={}, off={} (0x{:X})", hdr.field_ids_size, hdr.field_ids_off, hdr.field_ids_off);
    println!("  method_ids:      size={}, off={} (0x{:X})", hdr.method_ids_size, hdr.method_ids_off, hdr.method_ids_off);
    println!("  class_defs:      size={}, off={} (0x{:X})", hdr.class_defs_size, hdr.class_defs_off, hdr.class_defs_off);
    println!("  data_size:       {} (0x{:X})", hdr.data_size, hdr.data_size);
    println!("  data_off:        {} (0x{:X})", hdr.data_off, hdr.data_off);
    println!("  (actual file: {} bytes)", buf.len());
}

fn dump_map_list(buf: &[u8], map_off: u32) {
    if map_off == 0 {
        println!("=== Map List: NONE (map_off=0) ===");
        return;
    }
    let off = map_off as usize;
    let size = read_u32(buf, off);
    println!("\n=== Map List ({} items) ===", size);
    println!("  {:<8} {:<8} {:<8} {:<12} {}", "TYPE", "SIZE", "OFFSET", "OFFSET(hex)", "NAME");
    println!("  {:-<8} {:-<8} {:-<8} {:-<12} {:-}", "", "", "", "", "");

    let type_names: std::collections::HashMap<u32, &str> = [
        (0x0000, "kDexTypeHeaderItem"),
        (0x0001, "kDexTypeStringIdItem"),
        (0x0002, "kDexTypeTypeIdItem"),
        (0x0003, "kDexTypeProtoIdItem"),
        (0x0004, "kDexTypeFieldIdItem"),
        (0x0005, "kDexTypeMethodIdItem"),
        (0x0006, "kDexTypeClassDefItem"),
        (0x1000, "kDexTypeMapList"),
        (0x1001, "kDexTypeTypeList"),
        (0x1002, "kDexTypeAnnotationSetRefList"),
        (0x1003, "kDexTypeAnnotationSetItem"),
        (0x2000, "kDexTypeClassDataItem"),
        (0x2001, "kDexTypeCodeItem"),
        (0x2002, "kDexTypeStringDataItem"),
        (0x2003, "kDexTypeDebugInfoItem"),
        (0x2004, "kDexTypeAnnotationItem"),
        (0x2005, "kDexTypeEncodedArrayItem"),
        (0x2006, "kDexTypeAnnotationsDirectoryItem"),
    ]
    .iter()
    .cloned()
    .collect();

    for i in 0..size as usize {
        let item_off = off + 4 + i * 12;
        if item_off + 12 > buf.len() {
            println!("  [TRUNCATED at item {}]", i);
            break;
        }
        let typ = read_u16(buf, item_off) as u32;
        let _unused = read_u16(buf, item_off + 2);
        let sz = read_u32(buf, item_off + 4);
        let offset = read_u32(buf, item_off + 8);
        let name = type_names.get(&typ).copied().unwrap_or("UNKNOWN");
        println!("  0x{:04X}  {:<8} {:#010x} {:#010x}  #{}", typ, sz, offset, offset, name);
    }
    println!();
}

fn dump_code_items_from_raw(buf: &[u8], code_items_first_off: u32, code_items_count: u32) {
    if code_items_count == 0 {
        println!("=== Code Items: NONE ===");
        return;
    }

    println!("\n=== Code Items ({} items, starting at 0x{:X}) ===", code_items_count, code_items_first_off);
    let mut cur_off = code_items_first_off as usize;

    for i in 0..code_items_count as usize {
        if cur_off + 16 > buf.len() {
            println!("  [CodeItem {}] TRUNCATED: need 16 bytes at offset {:#x}, file size {:#x}",
                i, cur_off, buf.len());
            break;
        }

        let registers_size = read_u16(buf, cur_off) as u32;
        let ins_size = read_u16(buf, cur_off + 2) as u32;
        let outs_size = read_u16(buf, cur_off + 4) as u32;
        let tries_size = read_u16(buf, cur_off + 6) as u32;
        let debug_info_off = read_u32(buf, cur_off + 8);
        let insns_size = read_u32(buf, cur_off + 12) as usize;

        let insns_bytes = insns_size * 2;
        let insns_end = cur_off + 16 + insns_bytes;
        let fits = insns_end <= buf.len();

        let try_items_end = if tries_size > 0 && fits {
            let try_off = (insns_end + 3) & !3;
            try_off + tries_size as usize * 8
        } else {
            insns_end
        };

        println!("  [CodeItem {}] offset={:#x}", i, cur_off);
        println!("    registers_size={}, ins_size={}, outs_size={}, tries_size={}",
            registers_size, ins_size, outs_size, tries_size);
        println!("    debug_info_off={:#x}, insns_size={} ({} bytes)",
            debug_info_off, insns_size, insns_bytes);

        if !fits {
            println!("    *** ERROR: insns overflow past file end! Need {} more bytes ***",
                insns_end - buf.len());
            // Don't advance, just break to avoid infinite loop
            break;
        }
        if tries_size > 0 {
            let try_off = (insns_end + 3) & !3;
            let try_end = try_off + tries_size as usize * 8;
            if try_end > buf.len() {
                println!("    *** ERROR: try_items overflow! Need {} more bytes ***", try_end - buf.len());
                break;
            }
        }

        println!("    OK - next at {:#x}", try_items_end);

        cur_off = try_items_end;
        // Align to 4 for next code_item
        cur_off = (cur_off + 3) & !3;
        if cur_off > buf.len() {
            println!("    *** Next code_item at {:#x} is beyond file! ***", cur_off);
            break;
        }
    }
}

fn dump_dex(buf: &[u8], label: &str) {
    println!("\n\n");
    println!("======================================================================");
    println!("  {} ({} bytes)", label, buf.len());
    println!("======================================================================");

    if buf.len() < 8 || &buf[0..4] != b"dex\n" {
        println!("  [Not a valid DEX file - bad magic]");
        return;
    }

    dump_header(buf);

    let hdr = parse_header(buf);

    // Dump map_list
    if hdr.map_off > 0 && (hdr.map_off as usize) < buf.len() {
        dump_map_list(buf, hdr.map_off);
    } else {
        println!("\n=== Map List: NONE (off={:#x}, file_len={:#x}) ===", hdr.map_off, buf.len());
    }

    // Find code_items from map_list
    if hdr.map_off > 0 && (hdr.map_off as usize) + 4 <= buf.len() {
        let off = hdr.map_off as usize;
        let map_size = read_u32(buf, off);
        for i in 0..map_size as usize {
            let item_off = off + 4 + i * 12;
            if item_off + 12 > buf.len() { break; }
            let typ = read_u16(buf, item_off) as u32;
            let sz = read_u32(buf, item_off + 4);
            let offset = read_u32(buf, item_off + 8);
            if typ == 0x2001 {
                dump_code_items_from_raw(buf, offset, sz);
            }
        }
    }

    println!("\n  Data section: off={:#x}, size={:#x} (range [{:#x}, {:#x}) )",
        hdr.data_off, hdr.data_size, hdr.data_off, hdr.data_off + hdr.data_size);
    if hdr.data_off + hdr.data_size > buf.len() as u32 {
        println!("  *** WARNING: data section exceeds file size! ***");
    }
    println!();
}

fn format_class_name(name: &str) -> String {
    let mut name = name.replace('.', "/");
    if !name.starts_with('L') {
        name = format!("L{}", name);
    }
    if !name.ends_with(';') {
        name = format!("{};", name);
    }
    name
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dump_dex <dex_file> [class_name]");
        eprintln!("  If class_name is provided:");
        eprintln!("    - loads the DEX");
        eprintln!("    - runs extract_and_rebuild() for the class");
        eprintln!("    - saves rebuilt DEX to <dex_file>.rebuilt.dex");
        eprintln!("    - dumps both original and rebuilt DEX");
        eprintln!("  Otherwise, just dumps the given DEX file");
        return;
    }

    let dex_path = &args[1];

    // Read the DEX file
    let mut f = fs::File::open(dex_path).expect("Failed to open file");
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).expect("Failed to read file");

    dump_dex(&buf, &format!("DEX: {}", dex_path));

    if args.len() >= 3 {
        let class_name = &args[2];
        println!("\n\n=== Rebuilding class: {} ===", class_name);

        let formatted_class = format_class_name(class_name);
        println!("Formatted class name: {}", formatted_class);

        // Rebuild using DexManager
        let mut dex_mgr = DexManager::from_bytes(buf, false);
        let rebuilt = dex_mgr.extract_and_rebuild(&formatted_class);

        let out_path = format!("{}.rebuilt.dex", dex_path);
        fs::write(&out_path, &rebuilt).expect("Failed to write rebuilt DEX");
        println!("Rebuilt DEX saved to: {}", out_path);

        dump_dex(&rebuilt, &format!("Rebuilt: {}", out_path));
    }
}
