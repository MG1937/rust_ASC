//! DEX extraction and rebuild pipeline.
//!
//! Mirrors Python `asc_core/core`: `DexManager` is the only orchestrator and the
//! stage order is fixed: DvmInterpreter -> DexHollower -> DexIndexMapper ->
//! DexBuilder.
//!
//! Rules:
//! - In-memory DEX only: no APK reads, no ZIP parsing, no CLI output.
//! - New stages must be wired through `DexManager::extract_and_rebuild`; callers
//!   must not assemble intermediate stages themselves.
//! - Reuse `utils` for DEX primitives (tables, uleb128, string decoding); do not
//!   reimplement them here.
//! - This layer must not depend on `findrefs`: reference search and class
//!   rebuild are independent pipelines.
pub mod dex;
pub mod dvm_handlers;
pub mod dvm_interpreter;