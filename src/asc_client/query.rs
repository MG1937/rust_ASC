//! Request-local, fallible APK queries.
use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use cesu8::to_java_cesu8;
use memmap2::{Mmap, MmapOptions};

use super::apk::dex_reader::{_dex_defines_class, list_dex_classes};
use super::apk::loader::{_inflate_dex, DexEntry, checked_dex_entries, try_extract_zip_entry};
use super::asc_handler::{AscHandler, Reference};
use super::dex_container::into_logical_dex_buffers;
use super::manifest_handler::decode_manifest_xml;
use super::query_input::_format_class_name;
use crate::asc_core::findrefs::findrefs_manager::FindRefInput;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryErrorCode {
    InvalidArgument,
    FileNotFound,
    AccessDenied,
    IoError,
    InvalidFormat,
    NotFound,
    QueryFailed,
    Cancelled,
}

impl QueryErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::FileNotFound => "FILE_NOT_FOUND",
            Self::AccessDenied => "ACCESS_DENIED",
            Self::IoError => "IO_ERROR",
            Self::InvalidFormat => "INVALID_FORMAT",
            Self::NotFound => "NOT_FOUND",
            Self::QueryFailed => "QUERY_FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

#[derive(Debug)]
pub struct QueryError {
    pub code: QueryErrorCode,
    pub message: String,
}

impl QueryError {
    pub fn new(code: QueryErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(QueryErrorCode::InvalidArgument, message)
    }

    fn format(message: impl Into<String>) -> Self {
        Self::new(QueryErrorCode::InvalidFormat, message)
    }

    fn io(error: io::Error) -> Self {
        let code = match error.kind() {
            io::ErrorKind::NotFound => QueryErrorCode::FileNotFound,
            io::ErrorKind::PermissionDenied => QueryErrorCode::AccessDenied,
            _ => QueryErrorCode::IoError,
        };
        Self::new(code, error.to_string())
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}
impl std::error::Error for QueryError {}

#[derive(Debug)]
#[cfg_attr(feature = "mcp", derive(serde::Serialize, schemars::JsonSchema))]
pub struct ClassSource {
    pub class_name: String,
    pub dex_name: String,
    pub source: String,
}

/// The mapped input must remain unchanged until the query completes.
pub struct ApkQuery {
    data: Mmap,
    entries: Vec<DexEntry>,
    workers: usize,
}

impl ApkQuery {
    pub fn new(path: &str, workers: usize) -> Result<Self, QueryError> {
        if !Path::new(path).is_absolute() {
            return Err(QueryError::invalid("apk_path must be an absolute path"));
        }
        if workers == 0 {
            return Err(QueryError::invalid("worker count must be positive"));
        }
        // Reject FIFOs before open, which could otherwise block.
        let metadata = std::fs::metadata(path).map_err(QueryError::io)?;
        if !metadata.is_file() {
            return Err(QueryError::invalid("apk_path must identify a regular file"));
        }
        if metadata.len() == 0 {
            return Err(QueryError::format("empty APK"));
        }
        let file = File::open(path).map_err(QueryError::io)?;
        // SAFETY: callers must not modify the mapped file.
        let data = unsafe { MmapOptions::new().map(&file) }.map_err(QueryError::io)?;
        let entries = checked_dex_entries(&data).map_err(QueryError::format)?;
        Ok(Self {
            data,
            entries,
            workers,
        })
    }

    // Preserve archive order; only single-class lookup may stop early.
    fn scan<T: Send>(
        &self,
        first_hit: bool,
        visit: impl Fn(&DexEntry) -> Result<Option<T>, QueryError> + Sync,
    ) -> Result<Vec<T>, QueryError> {
        let next = AtomicUsize::new(0);
        let stopped = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..self.workers.min(self.entries.len()) {
                let visit = &visit;
                let next = &next;
                let stopped = &stopped;
                handles.push(scope.spawn(move || {
                    let mut results = Vec::new();
                    while !stopped.load(Ordering::Relaxed) {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(entry) = self.entries.get(index) else {
                            break;
                        };
                        let result = visit(entry);
                        if first_hit && matches!(result, Ok(Some(_))) {
                            stopped.store(true, Ordering::Relaxed);
                        }
                        results.push((index, result));
                    }
                    results
                }));
            }
            let mut results = Vec::new();
            let mut failed = false;
            for handle in handles {
                match handle.join() {
                    Ok(items) => results.extend(items),
                    Err(_) => failed = true,
                }
            }
            if failed {
                return Err(QueryError::new(
                    QueryErrorCode::QueryFailed,
                    "query worker panicked",
                ));
            }
            results.sort_by_key(|(index, _)| *index);
            let mut output = Vec::new();
            for (_, result) in results {
                if let Some(value) = result? {
                    output.push(value);
                }
            }
            Ok(output)
        })
    }

    fn dex_buffers(&self, entry: &DexEntry) -> Result<Vec<(String, Vec<u8>)>, QueryError> {
        let data = _inflate_dex(&self.data, entry, None)
            .map_err(QueryError::format)?
            .ok_or_else(|| QueryError::format("unexpected interrupted inflate"))?;
        validate_dex(&data)?;
        // Reject broken containers before the legacy single-DEX fallback.
        if data.starts_with(b"dex\n041\0") {
            let mut offset = 0;
            while offset < data.len() {
                let member = &data[offset..];
                validate_dex_header(member)?;
                if !member.starts_with(b"dex\n041\0") {
                    return Err(QueryError::format("invalid DEX 041 member"));
                }
                offset += u32_at(member, 0x20) as usize;
            }
        }
        let buffers = into_logical_dex_buffers(&entry.name, data);
        for (_, data) in &buffers {
            validate_dex(data)?;
        }
        Ok(buffers)
    }

    pub fn getclass(&self, class_name: &str) -> Result<ClassSource, QueryError> {
        let class_name = _format_class_name(class_name).map_err(QueryError::invalid)?;
        let target = to_java_cesu8(&class_name);
        let hits = self.scan(true, |entry| {
            for (dex_name, data) in self.dex_buffers(entry)? {
                if _dex_defines_class(&data, &target).map_err(QueryError::format)? {
                    return Ok(Some((dex_name, data)));
                }
            }
            Ok(None)
        })?;
        let (dex_name, data) = hits.into_iter().next().ok_or_else(|| {
            QueryError::new(
                QueryErrorCode::NotFound,
                format!("class {class_name} not found"),
            )
        })?;
        let source = AscHandler::new(false)
            .try_getclass(&data, &class_name)
            .map_err(|message| QueryError::new(QueryErrorCode::QueryFailed, message))?;
        Ok(ClassSource {
            class_name,
            dex_name,
            source,
        })
    }

    pub fn listclass(&self, prefix: Option<&str>) -> Result<Vec<String>, QueryError> {
        let prefix = prefix
            .map(str::trim)
            .map(|prefix| {
                if prefix.is_empty() {
                    return Err(QueryError::invalid("class prefix cannot be empty"));
                }
                Ok(if prefix.starts_with('L') {
                    prefix.to_owned()
                } else {
                    format!("L{}", prefix.replace('.', "/"))
                })
            })
            .transpose()?;
        let bytes = prefix
            .as_deref()
            .filter(|p| p.is_ascii())
            .map(str::as_bytes);
        let groups = self.scan(false, |entry| {
            let mut names = Vec::new();
            for (_, data) in self.dex_buffers(entry)? {
                names.extend(
                    list_dex_classes(&data, prefix.as_deref(), bytes)
                        .map_err(QueryError::format)?,
                );
            }
            Ok(Some(names))
        })?;
        Ok(groups.into_iter().flatten().collect())
    }

    pub fn findrefs(&self, kind: &str, find: &FindRefInput) -> Result<Vec<Reference>, QueryError> {
        if !matches!(kind, "string" | "type" | "method" | "field") {
            return Err(QueryError::invalid("unknown reference kind"));
        }
        let groups = self.scan(false, |entry| {
            let mut records = Vec::new();
            for (name, data) in self.dex_buffers(entry)? {
                records.extend(AscHandler::new(false).findrefs_records(&name, data, kind, find));
            }
            Ok(Some(records))
        })?;
        let mut records: Vec<_> = groups.into_iter().flatten().collect();
        records.sort_by(|a, b| a.dex_name.cmp(&b.dex_name));
        Ok(records)
    }

    pub fn getmanifest(&self) -> Result<String, QueryError> {
        let data = try_extract_zip_entry(&self.data, "AndroidManifest.xml")
            .map_err(QueryError::format)?
            .ok_or_else(|| {
                QueryError::new(QueryErrorCode::NotFound, "AndroidManifest.xml not found")
            })?;
        decode_manifest_xml(&data, true).map_err(QueryError::format)
    }
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn validate_dex_header(data: &[u8]) -> Result<(), QueryError> {
    if data.len() < 0x70
        || !data.starts_with(b"dex\n")
        || data[7] != 0
        || !data[4..7].iter().all(u8::is_ascii_digit)
    {
        return Err(QueryError::format("invalid DEX header"));
    }
    let size = u32_at(data, 0x20) as usize;
    let header = u32_at(data, 0x24) as usize;
    let expected = if &data[4..7] == b"041" { 0x78 } else { 0x70 };
    if header != expected || size < header || size > data.len() || u32_at(data, 0x28) != 0x1234_5678
    {
        return Err(QueryError::format("invalid DEX size/header/endianness"));
    }
    Ok(())
}

fn validate_dex(data: &[u8]) -> Result<(), QueryError> {
    validate_dex_header(data)?;
    for (index, width) in [4usize, 4, 12, 8, 8, 32].into_iter().enumerate() {
        let count = u32_at(data, 0x38 + index * 8) as usize;
        let start = u32_at(data, 0x3c + index * 8) as usize;
        if count != 0
            && (start == 0
                || count
                    .checked_mul(width)
                    .and_then(|size| start.checked_add(size))
                    .is_none_or(|end| end > data.len()))
        {
            return Err(QueryError::format("invalid DEX table range"));
        }
    }
    // Reject malformed strings instead of the legacy locators' empty fallback.
    let strings = u32_at(data, 0x38) as usize;
    let string_start = u32_at(data, 0x3c) as usize;
    for index in 0..strings {
        let offset = u32_at(data, string_start + index * 4) as usize;
        let tail = data
            .get(offset..)
            .filter(|_| offset != 0)
            .ok_or_else(|| QueryError::format("invalid DEX string offset"))?;
        let prefix = tail
            .iter()
            .take(5)
            .position(|byte| byte & 0x80 == 0)
            .ok_or_else(|| QueryError::format("invalid DEX string length"))?
            + 1;
        if memchr::memchr(0, &tail[prefix..]).is_none() {
            return Err(QueryError::format("unterminated DEX string"));
        }
    }
    let types = u32_at(data, 0x40) as usize;
    let type_start = u32_at(data, 0x44) as usize;
    for index in 0..types {
        if u32_at(data, type_start + index * 4) as usize >= strings {
            return Err(QueryError::format("invalid DEX type string index"));
        }
    }
    Ok(())
}
