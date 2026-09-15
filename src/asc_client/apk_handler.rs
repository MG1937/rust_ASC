// Auth: MG1937
// Strict 1:1 translation from Python apk_handler.py
//
// Manual ZIP parsing (Central Directory / Local Header / EOCD) + DEFLATE decompression.
// Parallel search uses std::thread + Arc<AtomicBool> for stop-event semantics.

use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use flate2::read::DeflateDecoder;
use memmap2::{Mmap, MmapOptions};

use crate::asc_client::asc_handler::AscHandler;
use crate::asc_core::findrefs::findrefs_manager::FindRefInput;
use crate::asc_client::dex_container::iter_logical_dex_buffers;

// ---------- ZIP constants ----------

const _CD_SIG: &[u8] = b"PK\x01\x02";
const _LH_SIG: &[u8] = b"PK\x03\x04";
const _EOCD_SIG: &[u8] = b"PK\x05\x06";
const _DEX_SUFFIX: &[u8] = b".dex";
const _DEFLATE_CHUNK: usize = 1 << 19; // 512 KiB

// ---------- helper: struct-like unpack ----------

#[inline]
fn _u32_from(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn _u16_from(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

// ---------- data structures ----------

#[derive(Clone, Debug)]
struct DexEntry {
    name: String,
    uncomp_size: u32,
    comp_size: u32,
    local_header_off: u32,
    comp_method: u16,
}

// ---------- ZIP helpers ----------

fn _find_eocd(buf: &[u8]) -> Option<usize> {
    let search_start = if buf.len() > 65536 + 22 {
        buf.len() - 65536 - 22
    } else {
        0
    };
    // search backwards
    let end = buf.len().saturating_sub(22);
    let mut pos = end;
    while pos >= search_start {
        if buf[pos..pos + 4] == *_EOCD_SIG {
            return Some(pos);
        }
        pos = pos.saturating_sub(1);
    }
    None
}

fn _parse_cd_dex_entries(buf: &[u8]) -> Vec<DexEntry> {
    let eocd_off = _find_eocd(buf).expect("EOCD not found");
    let cd_size = _u32_from(buf, eocd_off + 12) as usize;
    let cd_off = _u32_from(buf, eocd_off + 16) as usize;
    let cd_end = cd_off + cd_size;

    let mut entries: Vec<DexEntry> = Vec::new();
    let mut seen_names: Vec<Vec<u8>> = Vec::new();

    // ---- fast path: find "classes" literal ----
    let mut pos = cd_off;
    loop {
        let found = memchr(b"classes", &buf[pos..cd_end]);
        if found.is_none() {
            break;
        }
        let mpos = pos + found.unwrap();
        let header_off = mpos.wrapping_sub(46);
        pos = mpos + 7;

        if header_off < cd_off || buf[header_off..header_off + 4] != *_CD_SIG {
            continue;
        }

        let name_len = _u16_from(buf, header_off + 28) as usize;
        let name_start = mpos; // equivalent to pos - 7
        let name_end = name_start + name_len;
        if name_end > cd_end {
            continue;
        }

        let name_bytes = &buf[name_start..name_end];
        if !name_bytes.ends_with(_DEX_SUFFIX) || memchr(b"/",
            name_bytes).is_some() || seen_names.iter().any(|x| x.as_slice() == name_bytes)
        {
            continue;
        }

        seen_names.push(name_bytes.to_vec());
        entries.push(DexEntry {
            name: String::from_utf8_lossy(name_bytes).to_string(),
            uncomp_size: _u32_from(buf, header_off + 24),
            comp_size: _u32_from(buf, header_off + 20),
            local_header_off: _u32_from(buf, header_off + 42),
            comp_method: _u16_from(buf, header_off + 10),
        });
    }

    if !entries.is_empty() {
        return entries;
    }

    // ---- fallback: iterate every CD entry ----
    let mut ptr = cd_off;
    while ptr + 46 <= cd_end {
        if buf[ptr..ptr + 4] != *_CD_SIG {
            break;
        }
        let name_len = _u16_from(buf, ptr + 28) as usize;
        let extra_len = _u16_from(buf, ptr + 30) as usize;
        let comment_len = _u16_from(buf, ptr + 32) as usize;
        let name_start = ptr + 46;
        let name_end = name_start + name_len;
        let name_bytes = &buf[name_start..name_end];
        if name_bytes.ends_with(_DEX_SUFFIX) && memchr(b"/", name_bytes).is_none() {
            entries.push(DexEntry {
                name: String::from_utf8_lossy(name_bytes).to_string(),
                uncomp_size: _u32_from(buf, ptr + 24),
                comp_size: _u32_from(buf, ptr + 20),
                local_header_off: _u32_from(buf, ptr + 42),
                comp_method: _u16_from(buf, ptr + 10),
            });
        }
        ptr = name_end + extra_len + comment_len;
    }

    entries
}

/// Simple memchr for a needle slice within a haystack (avoids extra dependency).
fn memchr(needle: &[u8], haystack: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let end = haystack.len() - needle.len();
    for i in 0..=end {
        if haystack[i..i + needle.len()] == *needle {
            return Some(i);
        }
    }
    None
}

// ---------- DEFLATE ----------

fn _inflate_deflate_chunks(compressed: &[u8], stop: Option<&AtomicBool>) -> Option<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(compressed);
    let mut out = Vec::with_capacity(compressed.len() * 3); // rough estimate
    let mut chunk_buf = vec![0u8; _DEFLATE_CHUNK];

    loop {
        if let Some(s) = stop {
            if s.load(Ordering::SeqCst) {
                return None;
            }
        }
        match decoder.read(&mut chunk_buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk_buf[..n]),
            Err(_) => return None,
        }
    }

    if let Some(s) = stop {
        if s.load(Ordering::SeqCst) {
            return None;
        }
    }
    Some(out)
}

fn _inflate_dex(buf: &[u8], entry: &DexEntry, stop: Option<&AtomicBool>) -> Result<Vec<u8>, String> {
    let lh_off = entry.local_header_off as usize;
    if buf[lh_off..lh_off + 4] != *_LH_SIG {
        return Err("bad local header signature".to_string());
    }

    let name_len = _u16_from(buf, lh_off + 26) as usize;
    let extra_len = _u16_from(buf, lh_off + 28) as usize;
    let data_off = lh_off + 30 + name_len + extra_len;
    let comp_slice = &buf[data_off..data_off + entry.comp_size as usize];

    let data = if entry.comp_method == 0 {
        // stored
        comp_slice.to_vec()
    } else if entry.comp_method == 8 {
        // deflated
        match _inflate_deflate_chunks(comp_slice, stop) {
            Some(d) => d,
            None => return Ok(Vec::new()), // stopped
        }
    } else {
        return Err(format!("unsupported compression method: {}", entry.comp_method));
    };

    if entry.uncomp_size != 0 && data.len() != entry.uncomp_size as usize {
        return Err(format!(
            "size mismatch: expect {}, got {}",
            entry.uncomp_size,
            data.len()
        ));
    }
    Ok(data)
}

// ---------- DEX scan helpers ----------

fn _read_string_data_bytes(buf: &[u8], str_off: usize) -> &[u8] {
    // skip uleb128 size
    let mut pos = str_off;
    while buf[pos] & 0x80 != 0 {
        pos += 1;
    }
    pos += 1; // last byte of uleb128
    let start = pos;
    while pos < buf.len() && buf[pos] != 0 {
        pos += 1;
    }
    &buf[start..pos]
}

fn _find_type_idx(buf: &[u8], target_bytes: &[u8]) -> i32 {
    if buf.len() < 0x70 || buf[..3] != *b"dex" {
        return -1;
    }

    let string_ids_size = _u32_from(buf, 0x38) as usize;
    let string_ids_off = _u32_from(buf, 0x3C) as usize;
    let type_ids_size = _u32_from(buf, 0x40) as usize;
    let type_ids_off = _u32_from(buf, 0x44) as usize;

    if string_ids_size == 0 || type_ids_size == 0 {
        return -1;
    }
    if string_ids_off + string_ids_size * 4 > buf.len() {
        return -1;
    }
    if type_ids_off + type_ids_size * 4 > buf.len() {
        return -1;
    }

    let mut left: i32 = 0;
    let mut right: i32 = type_ids_size as i32 - 1;
    while left <= right {
        let mid = ((left + right) >> 1) as usize;
        let str_idx = _u32_from(buf, type_ids_off + (mid << 2)) as usize;
        if str_idx >= string_ids_size {
            return -1;
        }
        let str_off = _u32_from(buf, string_ids_off + (str_idx << 2)) as usize;
        if str_off >= buf.len() {
            return -1;
        }

        let cls_bytes = _read_string_data_bytes(buf, str_off);
        match cls_bytes.cmp(target_bytes) {
            std::cmp::Ordering::Equal => return mid as i32,
            std::cmp::Ordering::Less => left = mid as i32 + 1,
            std::cmp::Ordering::Greater => right = mid as i32 - 1,
        }
    }
    -1
}

fn _class_defs_contains_type_idx(buf: &[u8], type_idx: u32) -> bool {
    let class_defs_size = _u32_from(buf, 0x60) as usize;
    let class_defs_off = _u32_from(buf, 0x64) as usize;

    if class_defs_size == 0 {
        return false;
    }

    let class_defs_end = class_defs_off + (class_defs_size << 5);
    if class_defs_end > buf.len() {
        return false;
    }

    let needle = type_idx.to_le_bytes();
    let mut pos = class_defs_off;
    while pos + 4 <= class_defs_end {
        if let Some(found) = memchr(&needle, &buf[pos..class_defs_end]) {
            pos += found;
            if ((pos - class_defs_off) & 0x1F) == 0 {
                return true;
            }
            pos += 1;
        } else {
            break;
        }
    }
    false
}

fn _dex_defines_class(buf: &[u8], target_bytes: &[u8]) -> bool {
    let type_idx = _find_type_idx(buf, target_bytes);
    if type_idx < 0 {
        return false;
    }
    _class_defs_contains_type_idx(buf, type_idx as u32)
}

// ---------- worker helpers ----------

fn _inflate_and_hit(
    buf: &[u8],
    entry: &DexEntry,
    target_bytes: &[u8],
    stop: &AtomicBool,
    log: &dyn Fn(&str),
) -> (bool, Option<String>, Option<Vec<u8>>) {
    let tid = thread::current().id();
    let name = &entry.name;

    if stop.load(Ordering::SeqCst) {
        return (false, None, None);
    }

    let t0 = Instant::now();
    let data = match _inflate_dex(buf, entry, Some(stop)) {
        Ok(d) => d,
        Err(_) => return (false, None, None),
    };
    let t1 = Instant::now();

    if stop.load(Ordering::SeqCst) {
        return (false, None, None);
    }

    let mut hit = false;
    let mut hit_name = None;
    let mut hit_data = None;
    for (dex_name, dex_buf) in iter_logical_dex_buffers(name, &data) {
        if stop.load(Ordering::SeqCst) {
            return (false, None, None);
        }
        if _dex_defines_class(&dex_buf, target_bytes) {
            hit = true;
            hit_name = Some(dex_name);
            hit_data = Some(dex_buf);
            break;
        }
    }
    let t2 = Instant::now();

    if hit {
        stop.store(true, Ordering::SeqCst);
    }

    log(&format!(
        "[APK] [{:?}] '{}' inflate={:.2} us lookup={:.2} us hit={}",
        tid,
        name,
        (t1 - t0).as_secs_f64() * 1_000_000.0,
        (t2 - t1).as_secs_f64() * 1_000_000.0,
        hit
    ));
    (hit, hit_name, hit_data)
}

fn _findrefs_worker(
    buf: &[u8],
    entry: &DexEntry,
    find_type: &str,
    find: &FindRefInput,
) -> (String, Vec<String>, f64, f64) {
    let t0 = Instant::now();
    let data = _inflate_dex(buf, entry, None).unwrap_or_default();
    let t1 = Instant::now();

    let mut lines = Vec::new();
    let handler = AscHandler::new(false);
    for (dex_name, dex_buf) in iter_logical_dex_buffers(&entry.name, &data) {
        lines.extend(handler.findrefs(&dex_name, &dex_buf, find_type, find, true));
    }
    let t2 = Instant::now();

    (
        entry.name.clone(),
        lines,
        (t1 - t0).as_secs_f64() * 1_000_000.0,
        (t2 - t1).as_secs_f64() * 1_000_000.0,
    )
}

// ---------- ApkHandler ----------

pub struct ApkHandler {
    pub apk_path: String,
    pub debug: bool,
    pub max_workers: usize,
}

impl ApkHandler {
    pub fn new(apk_path: &str, debug: bool, max_workers: usize) -> Self {
        ApkHandler {
            apk_path: apk_path.to_string(),
            debug,
            max_workers,
        }
    }

    fn _log(&self, msg: &str) {
        if self.debug {
            println!("{}", msg);
        }
    }

    fn _read_apk(&self) -> Result<Mmap, String> {
        let fp = File::open(&self.apk_path)
            .map_err(|e| format!("cannot open APK: {}", e))?;
        unsafe {
            MmapOptions::new()
                .map(&fp)
                .map_err(|e| format!("cannot memory-map APK: {}", e))
        }
    }

    /// 在APK的所有DEX中搜索指定类，返回找到的DEX名称和数据
    pub fn get_class_dex(&self, dalvik_class: &str) -> Option<(String, Vec<u8>)> {
        let target_bytes = dalvik_class.as_bytes();
        let t_start = Instant::now();

        let apk_buf = match self._read_apk() {
            Ok(b) => b,
            Err(_) => return None,
        };

        let mut entries = _parse_cd_dex_entries(&apk_buf);
        entries.sort_by_key(|e| e.comp_size);

        if self.debug {
            let t_ready = Instant::now();
            self._log(&format!(
                "[APK] scan setup={:.2} us entries={}",
                (t_ready - t_start).as_secs_f64() * 1_000_000.0,
                entries.len()
            ));
        }

        if entries.is_empty() {
            return None;
        }

        let cap = std::cmp::min(
            entries.len(),
            std::cmp::max(6, std::cmp::min(self.max_workers, 12)),
        );

        let stop = Arc::new(AtomicBool::new(false));
        let apk_buf = Arc::new(apk_buf);
        let entries = Arc::new(entries);

        // Shared index counter for work stealing
        let work_queue = Arc::new(Mutex::new(0usize));
        let num_entries = entries.len();

        // Result storage
        let result = Arc::new(Mutex::new(None::<(String, Vec<u8>)>));

        let mut handles = Vec::with_capacity(cap);
        for _ in 0..cap {
            let stop = Arc::clone(&stop);
            let apk_buf = Arc::clone(&apk_buf);
            let entries = Arc::clone(&entries);
            let work_queue = Arc::clone(&work_queue);
            let result = Arc::clone(&result);
            let target_bytes = target_bytes.to_vec();

            let handler = ApkHandler::new(&self.apk_path, self.debug, self.max_workers);

            handles.push(thread::spawn(move || {
                loop {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    // Try to claim next entry
                    let idx = {
                        let mut counter = work_queue.lock().unwrap();
                        if *counter >= num_entries {
                            return;
                        }
                        let idx = *counter;
                        *counter += 1;
                        idx
                    };

                    let (hit, hit_name, hit_data) = _inflate_and_hit(
                        &apk_buf,
                        &entries[idx],
                        &target_bytes,
                        &stop,
                        &|msg| handler._log(msg),
                    );

                    if hit {
                        if let (Some(name), Some(data)) = (hit_name, hit_data) {
                            let mut res = result.lock().unwrap();
                            if res.is_none() {
                                *res = Some((name, data));
                            }
                        }
                        return;
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.join();
        }

        if self.debug {
            let t_end = Instant::now();
            self._log(&format!(
                "[APK] getclass total={:.2} us",
                (t_end - t_start).as_secs_f64() * 1_000_000.0
            ));
        }

        let result = result.lock().unwrap();
        result.clone()
    }

    /// 在APK的所有DEX中并行查找引用，返回结果列表
    pub fn for_each_findrefs(
        &self,
        find_type: &str,
        find: &FindRefInput,
    ) -> Vec<(String, Vec<String>)> {
        let t_start = Instant::now();

        let apk_buf = match self._read_apk() {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        let mut entries = _parse_cd_dex_entries(&apk_buf);
        entries.sort_by_key(|e| e.comp_size);

        if entries.is_empty() {
            return Vec::new();
        }

        let apk_buf = Arc::new(apk_buf);
        let entries = Arc::new(entries);
        let num_entries = entries.len();

        // Shared index counter for work stealing
        let work_queue = Arc::new(Mutex::new(0usize));

        let results = Arc::new(Mutex::new(Vec::<(String, Vec<String>)>::new()));
        let find = Arc::new((*find).clone());

        let num_workers = std::cmp::min(num_entries, self.max_workers);
        let mut handles = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let apk_buf = Arc::clone(&apk_buf);
            let entries = Arc::clone(&entries);
            let work_queue = Arc::clone(&work_queue);
            let results = Arc::clone(&results);
            let find_type = find_type.to_string();
            let find = Arc::clone(&find);

            handles.push(thread::spawn(move || {
                loop {
                    let idx = {
                        let mut counter = work_queue.lock().unwrap();
                        if *counter >= num_entries {
                            return;
                        }
                        let idx = *counter;
                        *counter += 1;
                        idx
                    };

                    let (name, lines, _inflate_us, _process_us) = _findrefs_worker(
                        &apk_buf,
                        &entries[idx],
                        &find_type,
                        &*find,
                    );
                    if !lines.is_empty() {
                        let mut res = results.lock().unwrap();
                        res.push((name, lines));
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.join();
        }

        let mut final_results = results.lock().unwrap().clone();

        // Sort by entry name for deterministic output
        final_results.sort_by(|a, b| a.0.cmp(&b.0));

        if self.debug {
            let t_end = Instant::now();
            self._log(&format!(
                "[APK] for_each_findrefs total={:.2} us count={} workers={}",
                (t_end - t_start).as_secs_f64() * 1_000_000.0,
                entries.len(),
                num_workers,
            ));
        }

        final_results
    }
}
