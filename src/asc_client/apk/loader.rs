// Auth: MG1937
// Strict 1:1 translation from Python apk/loader.py

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

use flate2::read::DeflateDecoder;
use libdeflater::Decompressor;

use crate::asc_core::utils::structs::{_STRUCT_H, _STRUCT_I};

const _CD_SIG: &[u8] = b"PK\x01\x02";
const _LH_SIG: &[u8] = b"PK\x03\x04";
const _EOCD_SIG: &[u8] = b"PK\x05\x06";
const _DEX_SUFFIX: &[u8] = b".dex";
const _DEFLATE_CHUNK: usize = 1 << 19;

#[derive(Clone, Debug)]
pub(crate) struct DexEntry {
    pub name: String,
    pub uncomp_size: u32,
    pub comp_size: u32,
    pub local_header_off: u32,
    pub comp_method: u16,
}

pub(crate) fn _find_eocd(buf: &[u8]) -> Option<usize> {
    if buf.len() < 22 {
        return None;
    }
    // EOCD can only be followed by a 65535-byte ZIP comment and its 22-byte
    // fixed header, so searching the whole APK is unnecessary.
    let search_start = buf.len().saturating_sub(65536 + 22);
    for pos in (search_start..=buf.len() - 22).rev() {
        if buf[pos..pos + 4] == *_EOCD_SIG {
            return Some(pos);
        }
    }
    None
}

pub(crate) fn _parse_cd_dex_entries(buf: &[u8]) -> Vec<DexEntry> {
    let Some(eocd_off) = _find_eocd(buf) else {
        return Vec::new();
    };

    let cd_size = _STRUCT_I::unpack_from(buf, eocd_off + 12) as usize;
    let cd_off = _STRUCT_I::unpack_from(buf, eocd_off + 16) as usize;
    let Some(cd_end) = cd_off.checked_add(cd_size).filter(|&end| end <= buf.len()) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    let mut seen_names = Vec::new();
    let mut pos = cd_off;

    // APKs normally name DEX files classes*.dex. Searching those bytes avoids
    // walking every resource entry in a large central directory.
    loop {
        let Some(found) = memchr::memmem::find(&buf[pos..cd_end], b"classes") else {
            break;
        };
        let header_off = pos + found;
        pos = header_off + 7;
        let header_off = header_off.wrapping_sub(46);
        if header_off < cd_off || buf[header_off..header_off + 4] != *_CD_SIG {
            continue;
        }

        let name_len = _STRUCT_H::unpack_from(buf, header_off + 28) as usize;
        let name_start = pos - 7;
        let Some(name_end) = name_start
            .checked_add(name_len)
            .filter(|&end| end <= cd_end)
        else {
            continue;
        };

        let name_bytes = &buf[name_start..name_end];
        if !name_bytes.ends_with(_DEX_SUFFIX)
            || name_bytes.contains(&b'/')
            || seen_names
                .iter()
                .any(|name: &Vec<u8>| name.as_slice() == name_bytes)
        {
            continue;
        }

        seen_names.push(name_bytes.to_vec());
        entries.push(DexEntry {
            name: String::from_utf8_lossy(name_bytes).to_string(),
            uncomp_size: _STRUCT_I::unpack_from(buf, header_off + 24),
            comp_size: _STRUCT_I::unpack_from(buf, header_off + 20),
            local_header_off: _STRUCT_I::unpack_from(buf, header_off + 42),
            comp_method: _STRUCT_H::unpack_from(buf, header_off + 10),
        });
    }

    if !entries.is_empty() {
        return entries;
    }

    // Fall back to a complete central-directory walk for valid but unusual ZIP
    // layouts where the name search cannot recover an entry header.
    let mut ptr = cd_off;
    while ptr + 46 <= cd_end {
        if buf[ptr..ptr + 4] != *_CD_SIG {
            break;
        }

        let name_len = _STRUCT_H::unpack_from(buf, ptr + 28) as usize;
        let extra_len = _STRUCT_H::unpack_from(buf, ptr + 30) as usize;
        let comment_len = _STRUCT_H::unpack_from(buf, ptr + 32) as usize;
        let name_start = ptr + 46;
        let Some(name_end) = name_start
            .checked_add(name_len)
            .filter(|&end| end <= cd_end)
        else {
            break;
        };
        let name_bytes = &buf[name_start..name_end];
        if name_bytes.ends_with(_DEX_SUFFIX) && !name_bytes.contains(&b'/') {
            entries.push(DexEntry {
                name: String::from_utf8_lossy(name_bytes).to_string(),
                uncomp_size: _STRUCT_I::unpack_from(buf, ptr + 24),
                comp_size: _STRUCT_I::unpack_from(buf, ptr + 20),
                local_header_off: _STRUCT_I::unpack_from(buf, ptr + 42),
                comp_method: _STRUCT_H::unpack_from(buf, ptr + 10),
            });
        }
        let Some(next_ptr) = name_end
            .checked_add(extra_len)
            .and_then(|off| off.checked_add(comment_len))
        else {
            break;
        };
        ptr = next_ptr;
    }

    entries
}

fn _inflate_deflate_chunks(compressed: &[u8], stop_event: &AtomicBool) -> Option<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(compressed);
    let mut out = Vec::with_capacity(compressed.len() * 3);
    let mut chunk_buf = vec![0u8; _DEFLATE_CHUNK];

    loop {
        if stop_event.load(Ordering::SeqCst) {
            return None;
        }
        match decoder.read(&mut chunk_buf) {
            Ok(0) => break,
            Ok(size) => out.extend_from_slice(&chunk_buf[..size]),
            Err(_) => return None,
        }
    }

    if stop_event.load(Ordering::SeqCst) {
        return None;
    }
    Some(out)
}

fn _compressed_data<'a>(buf: &'a [u8], entry: &DexEntry) -> Result<&'a [u8], String> {
    let local_header_off = entry.local_header_off as usize;
    if local_header_off
        .checked_add(30)
        .is_none_or(|header_end| header_end > buf.len())
        || buf[local_header_off..local_header_off + 4] != *_LH_SIG
    {
        return Err("bad local header signature".to_owned());
    }

    let name_len = _STRUCT_H::unpack_from(buf, local_header_off + 26) as usize;
    let extra_len = _STRUCT_H::unpack_from(buf, local_header_off + 28) as usize;
    // File data starts after the variable local filename and extra fields, not
    // at the corresponding central-directory record.
    let data_off = local_header_off
        .checked_add(30)
        .and_then(|off| off.checked_add(name_len))
        .and_then(|off| off.checked_add(extra_len))
        .ok_or_else(|| "bad local header range".to_owned())?;
    let data_end = data_off
        .checked_add(entry.comp_size as usize)
        .filter(|&end| end <= buf.len())
        .ok_or_else(|| "bad compressed data range".to_owned())?;
    Ok(&buf[data_off..data_end])
}

fn _validate_inflated_size(entry: &DexEntry, data: Vec<u8>) -> Result<Vec<u8>, String> {
    if entry.uncomp_size != 0 && data.len() != entry.uncomp_size as usize {
        return Err(format!(
            "size mismatch: expect {}, got {}",
            entry.uncomp_size,
            data.len()
        ));
    }
    Ok(data)
}

/// Inflate only as much of an entry as `need` asks for.
///
/// `listclass` only reads the DEX id tables plus the class descriptor strings,
/// which live in the first ~20-35% of a D8/R8 DEX; the remaining code/debug
/// sections never need to leave the deflate stream. `need` is re-evaluated on
/// each round and returns the prefix length required by the current data.
pub(crate) fn _inflate_dex_prefix_into<F>(
    buf: &[u8],
    entry: &DexEntry,
    out: &mut Vec<u8>,
    decompressor: &mut Decompressor,
    need: F,
) -> Result<(), String>
where
    F: Fn(&[u8]) -> Result<usize, String>,
{
    let comp_view = _compressed_data(buf, entry)?;
    out.clear();
    match entry.comp_method {
        0 => {
            out.extend_from_slice(comp_view);
            return Ok(());
        }
        8 => {}
        method => return Err(format!("unsupported compression method: {method}")),
    }

    let total = entry.uncomp_size as usize;
    // Low-level streaming API: `flate2`'s Read adapter copies through an
    // intermediate buffer, while `decompress` writes straight into `out`.
    let mut decoder = flate2::Decompress::new(false);
    let mut produced = 0usize;
    let mut step = 1usize << 20;
    let mut round = 0usize;
    loop {
        let target = need(&out[..produced])?.min(total);
        if produced >= target {
            out.truncate(produced);
            return Ok(());
        }
        // Some APKs keep class descriptors near the end of the DEX. Streaming
        // (flate2) decodes slower than the one-shot libdeflate path, so switch
        // back when the saving would be small.
        if round > 0 && target * 5 > total * 3 {
            return _inflate_dex_into_with(buf, entry, out, decompressor);
        }
        round += 1;

        let want = (target - produced).min(step);
        let consumed = decoder.total_in() as usize;
        out.resize(produced + want, 0);
        decoder
            .decompress(
                &comp_view[consumed..],
                &mut out[produced..produced + want],
                flate2::FlushDecompress::None,
            )
            .map_err(|error| format!("flate2 cannot decompress {}: {error}", entry.name))?;
        produced = decoder.total_out() as usize;
        if produced == 0 || (produced < target && consumed == decoder.total_in() as usize) {
            out.truncate(produced);
            return Err(format!(
                "size mismatch: expect {}, got {}",
                entry.uncomp_size,
                produced
            ));
        }
        step = (step * 2).min(8 << 20);
    }
}

/// Inflate one entry into a caller-owned buffer so a worker can reuse the same
/// pages across entries. Fresh multi-MB allocations must be zero-filled on
/// first touch, which roughly halves libdeflate's throughput; reusing a warm
/// buffer measured ~915 MB/s against ~460 MB/s for a fresh `Vec`.
pub(crate) fn _inflate_dex_into(
    buf: &[u8],
    entry: &DexEntry,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    _inflate_dex_into_with(buf, entry, out, &mut Decompressor::new())
}

/// Same as [`_inflate_dex_into`] with a reusable decompressor: libdeflate
/// builds its decode tables per instance, which measured ~7% of inflate time.
pub(crate) fn _inflate_dex_into_with(
    buf: &[u8],
    entry: &DexEntry,
    out: &mut Vec<u8>,
    decompressor: &mut Decompressor,
) -> Result<(), String> {
    let comp_view = _compressed_data(buf, entry)?;
    out.clear();
    match entry.comp_method {
        0 => out.extend_from_slice(comp_view),
        8 => {
            let size = entry.uncomp_size as usize;
            out.reserve(size);
            // SAFETY: `reserve` guarantees capacity for `size` bytes and every
            // byte is written by the decompressor before it is observed.
            unsafe { out.set_len(size) };
            let actual_size = decompressor
                .deflate_decompress(comp_view, out)
                .map_err(|error| {
                    format!("libdeflate cannot decompress {}: {error}", entry.name)
                })?;
            out.truncate(actual_size);
        }
        method => return Err(format!("unsupported compression method: {method}")),
    }
    if entry.uncomp_size != 0 && out.len() != entry.uncomp_size as usize {
        return Err(format!(
            "size mismatch: expect {}, got {}",
            entry.uncomp_size,
            out.len()
        ));
    }
    Ok(())
}

pub(crate) fn _inflate_dex(
    buf: &[u8],
    entry: &DexEntry,
    stop_event: Option<&AtomicBool>,
) -> Result<Option<Vec<u8>>, String> {
    let comp_view = _compressed_data(buf, entry)?;
    let data = match entry.comp_method {
        0 => comp_view.to_vec(),
        8 => match stop_event {
            // A single libdeflate call is faster when cancellation is unnecessary.
            None => {
                let mut data = Vec::with_capacity(entry.uncomp_size as usize);
                unsafe { data.set_len(entry.uncomp_size as usize) };
                let actual_size = Decompressor::new()
                    .deflate_decompress(comp_view, &mut data)
                    .map_err(|error| {
                        format!("libdeflate cannot decompress {}: {error}", entry.name)
                    })?;
                data.truncate(actual_size);
                data
            }
            Some(stop_event) => match _inflate_deflate_chunks(comp_view, stop_event) {
                Some(data) => data,
                None => return Ok(None),
            },
        },
        method => return Err(format!("unsupported compression method: {method}")),
    };

    _validate_inflated_size(entry, data).map(Some)
}

pub(crate) fn _extract_zip_entry(buf: &[u8], target_name: &str) -> Result<Vec<u8>, String> {
    let eocd_off = _find_eocd(buf).ok_or_else(|| "EOCD not found".to_owned())?;
    let cd_size = _STRUCT_I::unpack_from(buf, eocd_off + 12) as usize;
    let cd_off = _STRUCT_I::unpack_from(buf, eocd_off + 16) as usize;
    let cd_end = cd_off
        .checked_add(cd_size)
        .filter(|&end| end <= buf.len())
        .ok_or_else(|| "bad central directory range".to_owned())?;
    let target_bytes = target_name.as_bytes();
    let mut ptr = cd_off;

    while ptr + 46 <= cd_end {
        if buf[ptr..ptr + 4] != *_CD_SIG {
            return Err("bad central directory signature".to_owned());
        }
        let name_len = _STRUCT_H::unpack_from(buf, ptr + 28) as usize;
        let extra_len = _STRUCT_H::unpack_from(buf, ptr + 30) as usize;
        let comment_len = _STRUCT_H::unpack_from(buf, ptr + 32) as usize;
        let name_start = ptr + 46;
        let name_end = name_start
            .checked_add(name_len)
            .filter(|&end| end <= cd_end)
            .ok_or_else(|| "bad central directory entry range".to_owned())?;

        if &buf[name_start..name_end] == target_bytes {
            let entry = DexEntry {
                name: target_name.to_owned(),
                uncomp_size: _STRUCT_I::unpack_from(buf, ptr + 24),
                comp_size: _STRUCT_I::unpack_from(buf, ptr + 20),
                local_header_off: _STRUCT_I::unpack_from(buf, ptr + 42),
                comp_method: _STRUCT_H::unpack_from(buf, ptr + 10),
            };
            return _inflate_dex(buf, &entry, None)?.ok_or_else(|| "inflate stopped".to_owned());
        }

        ptr = name_end
            .checked_add(extra_len)
            .and_then(|off| off.checked_add(comment_len))
            .ok_or_else(|| "bad central directory entry range".to_owned())?;
    }

    Err(format!("{target_name} not found in APK"))
}
