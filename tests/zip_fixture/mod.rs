use std::path::Path;

use libdeflater::{crc32, CompressionLvl, Compressor};

#[derive(Clone, Copy)]
pub enum CompressionMethod {
    Stored,
    Deflated,
}

struct CentralEntry {
    name: Vec<u8>,
    method: u16,
    crc: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn compress(data: &[u8], method: CompressionMethod) -> (u16, Vec<u8>) {
    match method {
        CompressionMethod::Stored => (0, data.to_vec()),
        CompressionMethod::Deflated => {
            let mut compressor = Compressor::new(CompressionLvl::new(6).unwrap());
            let mut compressed = vec![0; compressor.deflate_compress_bound(data.len())];
            let size = compressor
                .deflate_compress(data, &mut compressed)
                .unwrap();
            compressed.truncate(size);
            (8, compressed)
        }
    }
}

pub fn write_apk(path: &Path, entries: &[(&str, &[u8])], compression: CompressionMethod) {
    let mut output = Vec::new();
    let mut central_entries = Vec::with_capacity(entries.len());

    for &(name, data) in entries {
        let name = name.as_bytes();
        let (method, compressed) = compress(data, compression);
        let local_header_offset = u32::try_from(output.len()).unwrap();
        let compressed_size = u32::try_from(compressed.len()).unwrap();
        let uncompressed_size = u32::try_from(data.len()).unwrap();
        let crc = crc32(data);

        push_u32(&mut output, 0x0403_4b50);
        push_u16(&mut output, 20);
        push_u16(&mut output, 0);
        push_u16(&mut output, method);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u32(&mut output, crc);
        push_u32(&mut output, compressed_size);
        push_u32(&mut output, uncompressed_size);
        push_u16(&mut output, u16::try_from(name.len()).unwrap());
        push_u16(&mut output, 0);
        output.extend_from_slice(name);
        output.extend_from_slice(&compressed);

        central_entries.push(CentralEntry {
            name: name.to_vec(),
            method,
            crc,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        });
    }

    let central_directory_offset = u32::try_from(output.len()).unwrap();
    for entry in &central_entries {
        push_u32(&mut output, 0x0201_4b50);
        push_u16(&mut output, 20);
        push_u16(&mut output, 20);
        push_u16(&mut output, 0);
        push_u16(&mut output, entry.method);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u32(&mut output, entry.crc);
        push_u32(&mut output, entry.compressed_size);
        push_u32(&mut output, entry.uncompressed_size);
        push_u16(&mut output, u16::try_from(entry.name.len()).unwrap());
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u32(&mut output, 0);
        push_u32(&mut output, entry.local_header_offset);
        output.extend_from_slice(&entry.name);
    }

    let central_directory_size =
        u32::try_from(output.len()).unwrap() - central_directory_offset;
    let entry_count = u16::try_from(central_entries.len()).unwrap();
    push_u32(&mut output, 0x0605_4b50);
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);
    push_u16(&mut output, entry_count);
    push_u16(&mut output, entry_count);
    push_u32(&mut output, central_directory_size);
    push_u32(&mut output, central_directory_offset);
    push_u16(&mut output, 0);

    std::fs::write(path, output).unwrap();
}
