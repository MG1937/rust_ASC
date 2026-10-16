// Auth: MG1937
// Strict 1:1 translation from Python apk_handler.py

use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use cesu8::to_java_cesu8;
use memmap2::{Mmap, MmapOptions};

use crate::asc_client::apk::dex_reader::{
    _dex_defines_class as _defines_class, list_dex_classes as _list_classes,
};
use crate::asc_client::apk::loader::{
    _inflate_dex as _load_dex, _parse_cd_dex_entries as _parse_entries, DexEntry,
};
use crate::asc_client::dex_container::iter_logical_dex_buffers;
use crate::asc_core::findrefs::findrefs_manager::FindRefInput;

fn _inflate_and_hit(
    mm: &[u8],
    entry: &DexEntry,
    target_bytes: &[u8],
    stop_event: Option<&AtomicBool>,
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
    let data = match _load_dex(mm, entry, stop_event) {
        Ok(Some(data)) => data,
        Ok(None) | Err(_) => return (false, None, None),
    };
    let t1 = Instant::now();
    if stop_event.is_some_and(|stop_event| stop_event.load(Ordering::SeqCst)) {
        return (false, None, None);
    }

    let mut hit = false;
    let mut hit_name = None;
    let mut hit_data = None;
    for (dex_name, dex_buf) in iter_logical_dex_buffers(name, &data) {
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
            let (ok, hit_name, hit_data) =
                _inflate_and_hit(&mm, &entries[0], &target_bytes, None, &|msg| self._log(msg));
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
                handles.push(thread::spawn(move || loop {
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

        let t_start = Instant::now();
        let mm = self._open_apk()?;
        let entries = _parse_entries(&mm);
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let workers = entries.len().min(self.max_workers);
        let entries = Arc::new(entries);
        let work_queue = Arc::new(Mutex::new(0usize));
        let results = Arc::new(Mutex::new(vec![None; entries.len()]));
        thread::scope(|scope| {
            for _ in 0..workers {
                let entries = Arc::clone(&entries);
                let work_queue = Arc::clone(&work_queue);
                let results = Arc::clone(&results);
                let prefix = prefix.as_deref();
                let prefix_bytes = prefix_bytes;
                let mm = &mm;
                scope.spawn(move || loop {
                    let index = {
                        let mut next = work_queue.lock().unwrap();
                        if *next >= entries.len() {
                            return;
                        }
                        let index = *next;
                        *next += 1;
                        index
                    };
                    let entry = &entries[index];
                    let result = _load_dex(mm, entry, None).and_then(|data| {
                        let data = data.ok_or_else(|| "inflate stopped".to_owned())?;
                        let mut names = Vec::new();
                        for (_dex_name, dex_buf) in iter_logical_dex_buffers(&entry.name, &data) {
                            names.extend(_list_classes(&dex_buf, prefix, prefix_bytes)?);
                        }
                        Ok((entry.name.clone(), names))
                    });
                    results.lock().unwrap()[index] = Some(result);
                });
            }
        });

        let mut names = Vec::new();
        let mut results = results.lock().unwrap();
        for result in results.iter_mut() {
            let (dex_name, dex_names) = result
                .take()
                .ok_or_else(|| "listclass worker did not return a result".to_owned())??;
            names.extend(dex_names.iter().cloned());
            self._log(&format!(
                "[APK] '{dex_name}' class_count={}",
                dex_names.len()
            ));
        }
        if self.debug {
            self._log(&format!(
                "[APK] listclass total={:.2} us count={} workers={workers}",
                t_start.elapsed().as_secs_f64() * 1_000_000.0,
                names.len(),
            ));
        }
        Ok(names)
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
                    if let Ok(result) = crate::asc_client::apk::worker::_findrefs_worker_from_buf(
                        &apk_buf,
                        &entries[index],
                        &find_type,
                        &find,
                        true,
                    ) {
                        results.push(result);
                    }
                }
                results
            }));
        }

        let mut final_results = Vec::new();
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
            if let Ok(result) = crate::asc_client::apk::worker::_findrefs_worker_from_buf(
                &apk_buf,
                &entries[index],
                find_type,
                &find,
                true,
            ) {
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
