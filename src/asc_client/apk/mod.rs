//! Internal APK loading helpers, used only by `ApkHandler`.
//!
//! Split:
//! - `loader`: ZIP central directory, local headers, inflate (prefix/full).
//! - `dex_reader`: lightweight DEX reads (class membership, class/method/string
//!   listings). No object model, no reference scanning.
//! - `worker`: per-DEX-entry findrefs task.
//!
//! Rules:
//! - This directory handles one entry at a time. Cross-entry scheduling,
//!   concurrency, cancellation and ordering belong to `apk_handler`.
//! - `dex_reader` must not depend on `findrefs`/`core::dex`; shared string
//!   matching or decoding logic goes to `asc_core/utils`.
//! - Do not add a second ZIP parser or inflate path; prefix and full inflate must
//!   reuse the same implementation in `loader`.
//! - Class/method/string listings belong to `dex_reader`; do not add listers
//!   under `asc_core/findrefs`.
pub(crate) mod dex_reader;
pub(crate) mod loader;
pub(crate) mod worker;
