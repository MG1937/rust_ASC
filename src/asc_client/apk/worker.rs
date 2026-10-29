// Auth: MG1937
// Strict 1:1 translation from Python apk/worker.py

use std::fs::File;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use memmap2::{Mmap, MmapOptions};

use crate::asc_client::apk::loader::{_inflate_dex_into_with, DexEntry};
use crate::asc_client::dex_container::{
    dex041_logical_offsets, into_logical_dex_buffers,
};
use crate::asc_core::findrefs::findrefs_manager::FindRefInput;

static _WORKER_APK_MM: OnceLock<Mutex<Option<(String, Arc<Mmap>)>>> = OnceLock::new();

fn _get_worker_apk_mm(apk_path: &str) -> Result<Arc<Mmap>, String> {
    // One worker handles several DEX entries from the same APK. Reusing its
    // read-only mapping avoids reopening a large archive for every task.
    let cache = _WORKER_APK_MM.get_or_init(|| Mutex::new(None));
    let mut cache = cache.lock().unwrap();
    if let Some((path, mm)) = cache.as_ref() {
        if path == apk_path {
            return Ok(Arc::clone(mm));
        }
    }

    let fp = File::open(apk_path).map_err(|error| format!("cannot open APK: {error}"))?;
    let mm = Arc::new(unsafe {
        MmapOptions::new()
            .map(&fp)
            .map_err(|error| format!("cannot memory-map APK: {error}"))?
    });
    *cache = Some((apk_path.to_owned(), Arc::clone(&mm)));
    Ok(mm)
}

pub(crate) fn _findrefs_worker_from_buf(
    apk_buf: &[u8],
    entry: &DexEntry,
    find_type: &str,
    find: &FindRefInput,
    aggregate: bool,
) -> Result<(String, Vec<String>, f64, f64, u32), String> {
    // Keep the decompiler graph out of CLI getclass/listclass startup. The
    // Python worker imports AscHandler only after receiving a findrefs task.
    use crate::asc_client::asc_handler::AscHandler;
    #[allow(unused_imports)]
    let _ = std::marker::PhantomData::<AscHandler>;

    let mut inflate_buf = Vec::new();
    let mut decompressor = libdeflater::Decompressor::new();
    _findrefs_worker_from_buf_into(
        apk_buf,
        entry,
        find_type,
        find,
        aggregate,
        &mut inflate_buf,
        &mut decompressor,
    )
}

/// Same as [`_findrefs_worker_from_buf`] but lets a worker thread keep one
/// warm inflate buffer across DEX entries.
pub(crate) fn _findrefs_worker_from_buf_into(
    apk_buf: &[u8],
    entry: &DexEntry,
    find_type: &str,
    find: &FindRefInput,
    aggregate: bool,
    inflate_buf: &mut Vec<u8>,
    decompressor: &mut libdeflater::Decompressor,
) -> Result<(String, Vec<String>, f64, f64, u32), String> {
    use crate::asc_client::asc_handler::AscHandler;

    let t0 = Instant::now();
    _inflate_dex_into_with(apk_buf, entry, inflate_buf, decompressor)?;
    let t1 = Instant::now();
    let mut lines = Vec::new();
    let handler = AscHandler::new(false);
    // A physical classes*.dex entry may contain several logical DEX files in
    // the DEX 041 container format; each needs an independent reference scan.
    if dex041_logical_offsets(inflate_buf).len() <= 1 {
        let data = std::mem::take(inflate_buf);
        let dex = crate::asc_core::utils::tinydex::DEX::from_vec(data, &entry.name);
        lines.extend(handler._findrefs(&entry.name, &dex, find_type, find, aggregate));
        *inflate_buf = dex.into_vec();
    } else {
        let data = std::mem::take(inflate_buf);
        for (dex_name, dex_buf) in into_logical_dex_buffers(&entry.name, data) {
            lines.extend(handler.findrefs_vec(&dex_name, dex_buf, find_type, find, aggregate));
        }
    }
    let t2 = Instant::now();
    Ok((
        entry.name.clone(),
        lines,
        (t1 - t0).as_secs_f64() * 1_000_000.0,
        (t2 - t1).as_secs_f64() * 1_000_000.0,
        std::process::id(),
    ))
}

pub(crate) fn _findrefs_worker_records_from_buf_into(
    apk_buf: &[u8],
    entry: &DexEntry,
    find_type: &str,
    find: &FindRefInput,
    aggregate: bool,
    display: crate::asc_client::asc_handler::FindRefsDisplayOptions,
    inflate_buf: &mut Vec<u8>,
    decompressor: &mut libdeflater::Decompressor,
) -> Result<(String, Vec<crate::asc_client::asc_handler::FindRefJsonRecord>, f64, f64, u32), String> {
    use crate::asc_client::asc_handler::AscHandler;

    let t0 = Instant::now();
    _inflate_dex_into_with(apk_buf, entry, inflate_buf, decompressor)?;
    let t1 = Instant::now();
    let mut records = Vec::new();
    let handler = AscHandler::new(false);
    if dex041_logical_offsets(inflate_buf).len() <= 1 {
        let data = std::mem::take(inflate_buf);
        let dex = crate::asc_core::utils::tinydex::DEX::from_vec(data, &entry.name);
        records.extend(handler._findrefs_records(
            &entry.name,
            &dex,
            find_type,
            find,
            aggregate,
            display,
        ));
        *inflate_buf = dex.into_vec();
    } else {
        let data = std::mem::take(inflate_buf);
        for (dex_name, dex_buf) in into_logical_dex_buffers(&entry.name, data) {
            let dex = crate::asc_core::utils::tinydex::DEX::from_vec(dex_buf, &dex_name);
            records.extend(handler._findrefs_records(
                &dex_name,
                &dex,
                find_type,
                find,
                aggregate,
                display,
            ));
        }
    }
    let t2 = Instant::now();
    Ok((
        entry.name.clone(),
        records,
        (t1 - t0).as_secs_f64() * 1_000_000.0,
        (t2 - t1).as_secs_f64() * 1_000_000.0,
        std::process::id(),
    ))
}

pub(crate) fn _findrefs_worker(
    apk_path: &str,
    entry: &DexEntry,
    find_type: &str,
    find: &FindRefInput,
    aggregate: bool,
) -> Result<(String, Vec<String>, f64, f64, u32), String> {
    let mm = _get_worker_apk_mm(apk_path)?;
    _findrefs_worker_from_buf(&mm, entry, find_type, find, aggregate)
}
