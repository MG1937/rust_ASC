//! Shared infrastructure (leaf layer).
//!
//! Contents:
//! - `tinydex`: lazy DEX object model (strings/types/protos/methods/fields/classes).
//! - `structs`/`leb128`: fixed-width DEX records and uleb128 reading.
//! - `dex_parser`/`dvm_regdec`: parsing and register-decoding helpers.
//! - `decompiler`: RadGuard decompiler adapter.
//!
//! Rules:
//! - Before reading DEX tables, strings, uleb128 or type descriptors, reuse the
//!   implementation here. Do not copy it into locators/scanners/client. Known
//!   duplicate: `apk/dex_reader`'s string reader vs
//!   `StringLocator::string_data_bytes`; when merged, this layer is authoritative.
//! - `tinydex` is the only object model. Prefer it whenever full class data is
//!   needed. Only explicit performance paths such as prefix probes may read
//!   tables directly in `apk/dex_reader`.
//! - This layer depends only on std and external crates; it must not depend on
//!   `asc_client`/`findrefs`/`core`.
pub mod decompiler;
pub mod dex_parser;
pub mod dvm_regdec;
pub mod leb128;
pub mod structs;
pub mod tinydex;
