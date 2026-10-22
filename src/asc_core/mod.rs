//! ASC core: in-memory DEX processing only; no APK/ZIP/CLI/MCP awareness.
//!
//! Dependency direction (one-way):
//! - `asc_client` -> `asc_core`; nothing here may `use crate::asc_client::*`.
//! - Shared DEX primitives belong in `utils`; `findrefs` and `core` must not
//!   depend on each other.
//!
//! Where new work goes:
//! - DEX table/string/uleb128 parsing and the object model -> `utils`
//! - Reference queries (string/type/method/field/extends/impl) -> `findrefs`
//! - Class extraction and DEX rebuild -> `core`
//!
//! Forbidden:
//! - Filesystem, mmap, ZIP, thread pools or any I/O/scheduling logic here.
//! - A second DEX scan pipeline for a CLI/MCP query; APK access and scheduling
//!   happen only in `asc_client::ApkHandler`.
pub mod core;
pub mod findrefs;
pub mod models;
pub mod utils;
