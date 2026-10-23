// Auth: MG1937
// Strict 1:1 translation from Python apk_handler.py

use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Instant;

use cesu8::to_java_cesu8;
use memmap2::{Mmap, MmapOptions};

use crate::asc_client::apk::dex_reader::{
    _dex_defines_class as _defines_class, class_defines_prefix_len, class_names_prefix_len,
    list_dex_classes, list_dex_strings, write_dex_class_names as _write_classes,
    write_dex_strings as _write_strings,
};
use crate::asc_client::apk::loader::{
    _inflate_dex as _load_dex, _inflate_dex_into, _inflate_dex_into_with,
    _inflate_dex_prefix_into, _parse_cd_dex_entries as _parse_entries, DexEntry,
};
use crate::asc_client::dex_container::{
    dex041_logical_offsets, into_logical_dex_buffers, iter_logical_dex_buffers,
};
use crate::asc_core::findrefs::findrefs_manager::FindRefInput;
use crate::asc_core::findrefs::scan::method_id_scan::render_dex_methods;

type DexChunkResult = Result<(Vec<Vec<u8>>, usize), String>;

/// Shared state for the ordered streaming pipeline.
struct StreamState {
    slots: Vec<Option<DexChunkResult>>,
    /// Next entry index the consumer still has to emit. Producers may not run
    /// further than `window` ahead of it, which bounds retained buffers.
    next_emit: usize,
    live: usize,
    stop: bool,
}

/// Decrements the live-worker count even if a worker unwinds, so the consumer
/// never blocks forever on a dead producer.
struct LiveGuard<'a> {
    state: &'a Mutex<StreamState>,
    ready: &'a Condvar,
}

impl Drop for LiveGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.live -= 1;
        }
        self.ready.notify_all();
    }
}

fn _inflate_and_hit(
    mm: &[u8],
    entry: &DexEntry,
    target_bytes: &[u8],
    stop_event: Option<&AtomicBool>,
    scratch: &mut Vec<u8>,
    decompressor: &mut libdeflater::Decompressor,
    log: &dyn Fn(&str),
) -> (bool, Option<String>, Option<Vec<u8>>) {
    let tid = format!("{:?}", thread::current().id());
    let tid = tid
        .strip_prefix("ThreadId(")
        .and_then(|tid| tid.strip_suffix(')'))
        .and_then(|tid| tid.parse::<u16>().ok())
        .unwrap_or_default();
    let name = &entry.name;
    // Multi-DEX lookup shares this event so a hit stops queued inflates and
    // logical-DEX scans. The single-entry fast path passes None.
    if stop_event.is_some_and(|stop_event| stop_event.load(Ordering::SeqCst)) {
        return (false, None, None);
    }

    let t0 = Instant::now();
    // Membership only needs the DEX id tables plus one descriptor string, so
    // most rejected entries decompress a small prefix instead of the whole file.
    let prefix_need = |data: &[u8]| class_defines_prefix_len(data, target_bytes);
    if _inflate_dex_prefix_into(mm, entry, scratch, decompressor, prefix_need).is_err() {
        return (false, None, None);
    }
    if stop_event.is_some_and(|stop_event| stop_event.load(Ordering::SeqCst)) {
        return (false, None, None);
    }
    if !matches!(iter_logical_dex_buffers(name, scratch).first(), Some((_, dex_buf)) if _defines_class(dex_buf, target_bytes).unwrap_or(false))
    {
        return (false, None, None);
    }
    // Confirmed: inflate this entry in full, then locate the class inside it.
    if _inflate_dex_into_with(mm, entry, scratch, decompressor).is_err() {
        return (false, None, None);
    }
    let t1 = Instant::now();
    if stop_event.is_some_and(|stop_event| stop_event.load(Ordering::SeqCst)) {
        return (false, None, None);
    }

    let mut hit = false;
    let mut hit_name = None;
    let mut hit_data = None;
    for (dex_name, dex_buf) in into_logical_dex_buffers(name, std::mem::take(scratch)) {
        if stop_event.is_some_and(|stop_event| stop_event.load(Ordering::SeqCst)) {
            return (false, None, None);
        }
        match _defines_class(&dex_buf, target_bytes) {
            Ok(true) => {
                hit = true;
                hit_name = Some(dex_name);
                hit_data = Some(dex_buf);
                break;
            }
            Ok(false) | Err(_) => {}
        }
    }
    let t2 = Instant::now();
    if hit {
        if let Some(stop_event) = stop_event {
            stop_event.store(true, Ordering::SeqCst);
        }
    }
    log(&format!(
        "[APK] [T{tid:04x}] '{name}' inflate={:.2} us lookup={:.2} us hit={hit}",
        (t1 - t0).as_secs_f64() * 1_000_000.0,
        (t2 - t1).as_secs_f64() * 1_000_000.0,
    ));
    (hit, hit_name, hit_data)
}

pub struct ApkHandler {
    pub apk_path: String,
    pub debug: bool,
    pub max_workers: usize,
}

impl ApkHandler {
    pub fn new(apk_path: &str, debug: bool, max_workers: usize) -> Self {
        ApkHandler {
            apk_path: apk_path.to_owned(),
            debug,
            max_workers,
        }
    }

    fn _log(&self, msg: &str) {
        if self.debug {
            println!("{msg}");
        }
    }

    fn _open_apk(&self) -> Result<Mmap, String> {
        let fp = File::open(&self.apk_path).map_err(|error| format!("cannot open APK: {error}"))?;
        unsafe {
            MmapOptions::new()
                .map(&fp)
                .map_err(|error| format!("cannot memory-map APK: {error}"))
        }
    }

    pub fn get_class_dex(&self, dalvik_class: &str) -> Option<(String, Vec<u8>)> {
        // DEX string_data_item uses MUTF-8. Non-BMP descriptors therefore need
        // CESU-8 bytes to preserve the table's UTF-16 code-unit ordering.
        let target_bytes =
            if !dalvik_class.is_ascii() && dalvik_class.chars().any(|ch| ch > '\u{ffff}') {
                to_java_cesu8(dalvik_class).into_owned()
            } else {
                dalvik_class.as_bytes().to_vec()
            };
        let t_start = Instant::now();
        let mm = self._open_apk().ok()?;
        let mut entries = _parse_entries(&mm);
        // Small compressed entries finish first, increasing the chance that
        // a hit cancels expensive inflates which have not started yet.
        entries.sort_by_key(|entry| entry.comp_size);
        if self.debug {
            self._log(&format!(
                "[APK] scan setup={:.2} us entries={}",
                t_start.elapsed().as_secs_f64() * 1_000_000.0,
                entries.len()
            ));
        }
        if entries.is_empty() {
            return None;
        }

        let (hit_name, hit_data) = if entries.len() == 1 && self.max_workers > 0 {
            // A thread pool cannot parallelize one item. Skipping it also lets
            // Deflate use the faster non-cancellable one-shot path.
            let mut scratch = Vec::new();
            let mut decompressor = libdeflater::Decompressor::new();
            let (ok, hit_name, hit_data) = _inflate_and_hit(
                &mm,
                &entries[0],
                &target_bytes,
                None,
                &mut scratch,
                &mut decompressor,
                &|msg| self._log(msg),
            );
            if ok {
                (hit_name, hit_data)
            } else {
                (None, None)
            }
        } else {
            let stop_event = Arc::new(AtomicBool::new(false));
            // Limit outstanding inflates even when the configured executor is
            // large; decompressed DEX buffers can consume substantial RAM.
            let cap = entries.len().min(6.max(self.max_workers.min(12)));
            let worker_count = cap.min(self.max_workers);
            let mm = Arc::new(mm);
            let entries = Arc::new(entries);
            let work_queue = Arc::new(Mutex::new(0usize));
            let result = Arc::new(Mutex::new(None));
            let mut handles = Vec::with_capacity(worker_count);

            for _ in 0..worker_count {
                let mm = Arc::clone(&mm);
                let entries = Arc::clone(&entries);
                let work_queue = Arc::clone(&work_queue);
                let result = Arc::clone(&result);
                let stop_event = Arc::clone(&stop_event);
                let target_bytes = target_bytes.clone();
                let debug = self.debug;
                handles.push(thread::spawn(move || {
                    // Reused across entries so decoded pages stay warm.
                    let mut scratch = Vec::new();
                    let mut decompressor = libdeflater::Decompressor::new();
                    loop {
                    if stop_event.load(Ordering::SeqCst) {
                        return;
                    }
                    let index = {
                        let mut next = work_queue.lock().unwrap();
                        if *next >= entries.len() {
                            return;
                        }
                        let index = *next;
                        *next += 1;
                        index
                    };
                    let (ok, hit_name, hit_data) = _inflate_and_hit(
                        &mm,
                        &entries[index],
                        &target_bytes,
                        Some(&stop_event),
                        &mut scratch,
                        &mut decompressor,
                        &|msg| {
                            if debug {
                                println!("{msg}");
                            }
                        },
                    );
                    if ok {
                        if let (Some(hit_name), Some(hit_data)) = (hit_name, hit_data) {
                            let mut result = result.lock().unwrap();
                            if result.is_none() {
                                *result = Some((hit_name, hit_data));
                            }
                        }
                        return;
                    }
                    }
                }));
            }
            for handle in handles {
                let _ = handle.join();
            }
            let result = result.lock().unwrap().take();
            match result {
                Some((hit_name, hit_data)) => (Some(hit_name), Some(hit_data)),
                None => (None, None),
            }
        };

        if self.debug {
            self._log(&format!(
                "[APK] getclass total={:.2} us",
                t_start.elapsed().as_secs_f64() * 1_000_000.0
            ));
        }
        hit_name.zip(hit_data)
    }

    /// List class descriptors as individual strings, preserving the row API.
    /// CLI consumers can use `for_each_class_chunk` to avoid collecting rows.
    pub fn list_classes(&self, prefix: Option<&str>) -> Result<Vec<String>, String> {
        if self.max_workers == 0 {
            return Err("Worker count must be greater than zero".to_owned());
        }
        let prefix = prefix
            .map(str::trim)
            .map(|prefix| {
                if prefix.is_empty() {
                    return Err("Class prefix cannot be empty".to_owned());
                }
                Ok(if prefix.starts_with('L') {
                    prefix.to_owned()
                } else {
                    format!("L{}", prefix.replace('.', "/"))
                })
            })
            .transpose()?;
        let prefix_bytes = prefix
            .as_deref()
            .filter(|prefix| prefix.is_ascii())
            .map(str::as_bytes);
        let mut rows = Vec::new();
        self._stream_dex_items(
            "class",
            |buf| {
                // Keep record boundaries instead of splitting serialized CLI
                // lines; the historical API does not validate descriptor syntax.
                let names = list_dex_classes(buf, prefix.as_deref(), prefix_bytes)?;
                let count = names.len();
                Ok((names.into_iter().map(String::into_bytes).collect(), count))
            },
            Some(&class_names_prefix_len),
            |bytes| {
                let name = String::from_utf8(bytes)
                    .map_err(|error| format!("invalid UTF-8 class name: {error}"))?;
                rows.push(name);
                Ok(())
            },
        )?;
        Ok(rows)
    }

    /// List defined method signatures in DEX declaration order.
    pub fn list_methods(
        &self,
        class: Option<&str>,
        filter: Option<&str>,
    ) -> Result<Vec<String>, String> {
        Ok(self
            .list_method_chunks(class, filter)?
            .iter()
            .flat_map(|text| text.lines().map(str::to_owned))
            .collect())
    }

    pub(crate) fn list_method_chunks(
        &self,
        class: Option<&str>,
        filter: Option<&str>,
    ) -> Result<Vec<String>, String> {
        self.list_method_bytes(class, filter).map(|chunks| {
            chunks
                .into_iter()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .collect()
        })
    }

    pub(crate) fn list_method_bytes(
        &self,
        class: Option<&str>,
        filter: Option<&str>,
    ) -> Result<Vec<Vec<u8>>, String> {
        let class = class
            .map(str::trim)
            .map(|name| {
                if name.is_empty() {
                    return Err("Class name cannot be empty".to_owned());
                }
                Ok(if name.starts_with('L') && name.ends_with(';') {
                    name.to_owned()
                } else {
                    format!("L{};", name.replace('.', "/"))
                })
            })
            .transpose()?;
        let filter = filter.map(str::to_lowercase);
        self._list_dex_items("method", |buf| {
            let (text, count) = render_dex_methods(buf, class.as_deref(), filter.as_deref())?;
            Ok((vec![text.into_bytes()], count))
        })
    }

    /// Streams per-DEX output in central-directory order through `emit`.
    ///
    /// Entries are inflated and rendered in parallel, but only one window of
    /// rendered buffers is retained at a time: a full list of every method in a
    /// 400 MB APK is hundreds of MB of text, and holding it all until the end
    /// dominated peak memory. Output order is unchanged (entry order), so the
    /// emitted bytes are identical.
    fn _stream_dex_items<F, E>(
        &self,
        kind: &str,
        list: F,
        need: Option<&(dyn Fn(&[u8]) -> Result<usize, String> + Sync)>,
        mut emit: E,
    ) -> Result<usize, String>
    where
        F: Fn(&[u8]) -> Result<(Vec<Vec<u8>>, usize), String> + Sync,
        E: FnMut(Vec<u8>) -> Result<(), String>,
    {
        if self.max_workers == 0 {
            return Err("Worker count must be greater than zero".to_owned());
        }

        let t_start = Instant::now();
        let mm = self._open_apk()?;
        let entries = _parse_entries(&mm);
        if entries.is_empty() {
            return Ok(0);
        }

        let workers = entries.len().min(self.max_workers);
        let mut total_count;

        // Bounded reorder pipeline: workers inflate and render out of order,
        // the consumer emits in central-directory order and the producer side
        // stalls once `window` rendered buffers are waiting. No barriers, so
        // parallelism is preserved while retained text stays bounded.
        let window = workers.max(1);
        let state = Mutex::new(StreamState {
            slots: vec![None; entries.len()],
            next_emit: 0,
            live: workers,
            stop: false,
        });
        let ready = Condvar::new();
        let next = AtomicUsize::new(0);

        total_count = thread::scope(|scope| -> Result<usize, String> {
            for _ in 0..workers {
                scope.spawn(|| {
                    let _live = LiveGuard { state: &state, ready: &ready };
                    // Reused across entries: keeps the decompressed pages warm.
                    let mut inflate_buf = Vec::new();
                    let mut decompressor = libdeflater::Decompressor::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(entry) = entries.get(index) else {
                            break;
                        };
                        let mut inflate = |buf: &mut Vec<u8>| match need {
                            Some(need) => {
                                _inflate_dex_prefix_into(&mm, entry, buf, &mut decompressor, need)
                            }
                            None => {
                                _inflate_dex_into_with(&mm, entry, buf, &mut decompressor)
                            }
                        };
                        let result = inflate(&mut inflate_buf).and_then(|()| {
                            let mut items = Vec::new();
                            let mut count = 0;
                            let mut offsets = dex041_logical_offsets(&inflate_buf);
                            if offsets.len() <= 1 {
                                let (dex_items, dex_count) = list(&inflate_buf)?;
                                items.extend(dex_items);
                                count += dex_count;
                            } else {
                                // DEX 041 containers need every logical DEX in
                                // full; the prefix path cannot be used for them.
                                offsets.clear();
                                _inflate_dex_into_with(
                                    &mm,
                                    entry,
                                    &mut inflate_buf,
                                    &mut decompressor,
                                )?;
                                for (_, dex_buf) in
                                    iter_logical_dex_buffers(&entry.name, &inflate_buf)
                                {
                                    let (dex_items, dex_count) = list(&dex_buf)?;
                                    items.extend(dex_items);
                                    count += dex_count;
                                }
                            }
                            Ok((items, count))
                        });
                        let mut guard = state.lock().unwrap();
                        // The consumer is waiting for the lowest unfinished
                        // index and never blocks producers at that index, so
                        // this wait can always be released.
                        while index >= guard.next_emit + window && !guard.stop {
                            guard = ready.wait(guard).unwrap();
                        }
                        if guard.stop {
                            return;
                        }
                        guard.slots[index] = Some(result);
                        drop(guard);
                        ready.notify_all();
                    }
                });
            }

            let mut emitted = 0usize;
            for index in 0..entries.len() {
                let result = {
                    let mut guard = state.lock().unwrap();
                    while guard.slots[index].is_none() {
                        if guard.live == 0 {
                            break;
                        }
                        guard = ready.wait(guard).unwrap();
                    }
                    match guard.slots[index].take() {
                        Some(result) => {
                            guard.next_emit = index + 1;
                            ready.notify_all();
                            result
                        }
                        None => Err(format!(
                            "list{kind} worker did not return a result for '{}'",
                            entries[index].name
                        )),
                    }
                };
                let (dex_items, count) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        // Release blocked producers before unwinding.
                        state.lock().unwrap().stop = true;
                        ready.notify_all();
                        return Err(error);
                    }
                };
                if self.debug {
                    self._log(&format!(
                        "[APK] '{}' {kind}_count={count}",
                        entries[index].name
                    ));
                }
                for item in dex_items {
                    if let Err(error) = emit(item) {
                        state.lock().unwrap().stop = true;
                        ready.notify_all();
                        return Err(error);
                    }
                }
                emitted += count;
            }
            Ok(emitted)
        })?;

        if self.debug {
            self._log(&format!(
                "[APK] list{kind} total={:.2} us count={total_count} workers={workers}",
                t_start.elapsed().as_secs_f64() * 1_000_000.0,
            ));
        }
        Ok(total_count)
    }

    fn _list_dex_items<F>(&self, kind: &str, list: F) -> Result<Vec<Vec<u8>>, String>
    where
        F: Fn(&[u8]) -> Result<(Vec<Vec<u8>>, usize), String> + Sync,
    {
        let mut items = Vec::new();
        self._stream_dex_items(kind, list, None, |chunk| {
            items.push(chunk);
            Ok(())
        })?;
        Ok(items)
    }

    /// Stream class names (one per line) in DEX declaration order.
    pub fn for_each_class_chunk<E>(&self, prefix: Option<&str>, mut emit: E) -> Result<usize, String>
    where
        E: FnMut(&[u8]) -> Result<(), String>,
    {
        let prefix = prefix
            .map(str::trim)
            .map(|prefix| {
                if prefix.is_empty() {
                    return Err("Class prefix cannot be empty".to_owned());
                }
                Ok(if prefix.starts_with('L') {
                    prefix.to_owned()
                } else {
                    format!("L{}", prefix.replace('.', "/"))
                })
            })
            .transpose()?;
        let prefix_bytes = prefix
            .as_deref()
            .filter(|prefix| prefix.is_ascii())
            .map(str::as_bytes);

        self._stream_dex_items(
            "class",
            |buf| {
                let mut names = Vec::new();
                let count = _write_classes(buf, prefix.as_deref(), prefix_bytes, &mut names)?;
                Ok((vec![names], count))
            },
            Some(&class_names_prefix_len),
            |chunk| emit(&chunk),
        )
    }

    /// Stream rendered method lines in DEX declaration order.
    pub fn for_each_method_chunk<E>(
        &self,
        class: Option<&str>,
        filter: Option<&str>,
        mut emit: E,
    ) -> Result<usize, String>
    where
        E: FnMut(&[u8]) -> Result<(), String>,
    {
        let class = class
            .map(str::trim)
            .map(|name| {
                if name.is_empty() {
                    return Err("Class name cannot be empty".to_owned());
                }
                Ok(if name.starts_with('L') && name.ends_with(';') {
                    name.to_owned()
                } else {
                    format!("L{};", name.replace('.', "/"))
                })
            })
            .transpose()?;
        let filter = filter.map(str::to_lowercase);
        self._stream_dex_items(
            "method",
            |buf| {
                let (text, count) = render_dex_methods(buf, class.as_deref(), filter.as_deref())?;
                Ok((vec![text.into_bytes()], count))
            },
            None,
            |chunk| emit(&chunk),
        )
    }

    /// List string pool values as individual records, preserving the row API.
    /// CLI consumers can use `for_each_string_chunk` to avoid collecting rows.
    pub fn list_strings(&self, filter: Option<&str>) -> Result<Vec<String>, String> {
        let filter = filter.map(str::to_lowercase);
        let mut rows = Vec::new();
        self._stream_dex_items(
            "string",
            |buf| {
                // One record per value: a pool can hold strings with newlines,
                // and the row API must not reframe them as CLI lines.
                let values = list_dex_strings(buf, filter.as_deref())?;
                let count = values.len();
                Ok((values.into_iter().map(String::into_bytes).collect(), count))
            },
            // Every string is potentially needed, so entries inflate in full.
            None,
            |bytes| {
                let value = String::from_utf8(bytes)
                    .map_err(|error| format!("invalid UTF-8 string value: {error}"))?;
                rows.push(value);
                Ok(())
            },
        )?;
        Ok(rows)
    }

    /// Stream string values (one per line) in DEX table order.
    pub fn for_each_string_chunk<E>(&self, filter: Option<&str>, mut emit: E) -> Result<usize, String>
    where
        E: FnMut(&[u8]) -> Result<(), String>,
    {
        let filter = filter.map(str::to_lowercase);
        self._stream_dex_items(
            "string",
            |buf| {
                let mut out = Vec::new();
                let count = _write_strings(buf, filter.as_deref(), &mut out)?;
                Ok((vec![out], count))
            },
            None,
            |chunk| emit(&chunk),
        )
    }

    pub fn for_each_findrefs(
        &self,
        find_type: &str,
        find: &FindRefInput,
    ) -> Vec<(String, Vec<String>)> {
        let t_start = Instant::now();
        let apk_buf = match self._open_apk() {
            Ok(apk_buf) => Arc::new(apk_buf),
            Err(_) => return Vec::new(),
        };
        let mut entries = _parse_entries(&apk_buf);
        entries.sort_by_key(|entry| {
            std::cmp::Reverse(entry.comp_size as u64 + entry.uncomp_size as u64 * 2 / 3)
        });
        if entries.is_empty() || self.max_workers == 0 {
            return Vec::new();
        }

        let entries = Arc::new(entries);
        let work_queue = Arc::new(Mutex::new(0usize));
        let find = Arc::new(find.clone());
        let workers = entries.len().min(self.max_workers);
        let mut handles = Vec::with_capacity(workers);

        for _ in 1..workers {
            let apk_buf = Arc::clone(&apk_buf);
            let entries = Arc::clone(&entries);
            let work_queue = Arc::clone(&work_queue);
            let find_type = find_type.to_owned();
            let find = Arc::clone(&find);
            handles.push(thread::spawn(move || {
                let mut results = Vec::new();
                // One warm decompression buffer per worker, reused per entry.
                let mut inflate_buf = Vec::new();
                let mut decompressor = libdeflater::Decompressor::new();
                loop {
                    let index = {
                        let mut next = work_queue.lock().unwrap();
                        if *next >= entries.len() {
                            break;
                        }
                        let index = *next;
                        *next += 1;
                        index
                    };
                    if let Ok(result) =
                        crate::asc_client::apk::worker::_findrefs_worker_from_buf_into(
                            &apk_buf,
                            &entries[index],
                            &find_type,
                            &find,
                            true,
                            &mut inflate_buf,
                            &mut decompressor,
                        )
                    {
                        results.push(result);
                    }
                }
                results
            }));
        }

        let mut final_results = Vec::new();
        let mut inflate_buf = Vec::new();
        let mut decompressor = libdeflater::Decompressor::new();
        loop {
            let index = {
                let mut next = work_queue.lock().unwrap();
                if *next >= entries.len() {
                    break;
                }
                let index = *next;
                *next += 1;
                index
            };
            if let Ok(result) =
                crate::asc_client::apk::worker::_findrefs_worker_from_buf_into(
                    &apk_buf,
                    &entries[index],
                    find_type,
                    &find,
                    true,
                    &mut inflate_buf,
                    &mut decompressor,
                )
            {
                final_results.push(result);
            }
        }
        for handle in handles {
            if let Ok(mut results) = handle.join() {
                final_results.append(&mut results);
            }
        }

        // Findrefs is intentionally streamed in completion order in Python.
        // The Rust CLI consumes this Vec after workers complete, so retain its
        // established deterministic name ordering.
        final_results.sort_by(|left, right| left.0.cmp(&right.0));
        if self.debug {
            for (dex_name, _lines, inflate_us, process_us, pid) in &final_results {
                self._log(&format!(
                    "[APK] [P{pid}] '{dex_name}' inflate={inflate_us:.2} us process={process_us:.2} us"
                ));
            }
            self._log(&format!(
                "[APK] for_each_findrefs total={:.2} us count={} workers={}",
                t_start.elapsed().as_secs_f64() * 1_000_000.0,
                entries.len(),
                self.max_workers,
            ));
        }
        final_results
            .into_iter()
            .map(|(dex_name, lines, _inflate_us, _process_us, _pid)| (dex_name, lines))
            .collect()
    }
}
