//! Client adapter layer: CLI, APK access, MCP.
//!
//! Dependency direction: `asc_client -> asc_core`; the reverse is forbidden.
//!
//! Boundaries (aligned with Python):
//! - `apk_handler`: the only APK/ZIP access and scheduling entry point; it owns
//!   mmap, entries, worker pools, cancellation and output ordering.
//! - `apk/`: loader (ZIP+inflate), dex_reader (lightweight DEX reads), worker
//!   (one DEX task).
//! - `asc_handler`: core orchestration and text formatting; never touches ZIP/APK.
//! - `cli`: argument parsing, invocation and output only; no scanning logic.
//! - `mcp`: thin adapter over CLI/ApkHandler; must not add a query pipeline.
//!
//! Forbidden:
//! - A second APK scan pipeline (the historical `query.rs/ApkQuery` was reverted;
//!   do not revive it).
//! - `apk/dex_reader` depending on `findrefs` locators. Shared matching/decoding
//!   logic must live in `asc_core/utils`.
pub(crate) mod apk;
pub mod apk_handler;
pub mod asc_handler;
pub mod dex_container;
pub mod manifest_handler;
