//! Reference-search domain.
//!
//! Python contract: `FindRefManager::find_ref` is the only query entry point.
//! - string/type/method/field: locate indices, then hand off to the code-item
//!   scanner.
//! - extends/impl: short-circuit inside `find_ref`, use the class-def scanner,
//!   and return class indices.
//!
//! Dependency direction:
//! - May depend on `utils` (tinydex/leb128/structs).
//! - Must not depend on `asc_client` or on the `core::dex` rebuild pipeline.
//! - `locator` and `scan` are implementation details; only `findrefs_manager`
//!   may call them.
//!
//! Forbidden:
//! - A second entry point for the same query (e.g. exposing scan/locate variants
//!   outside the manager).
//! - Duplicate DEX table parsing: use locators for index location and scanners
//!   for opcode scans.
//! - Building another object model in hot scan paths; when full class data is
//!   needed, use the lazy accessors in `utils::tinydex` instead of writing a
//!   one-off parser.
pub mod findrefs_manager;
pub mod locator;
pub mod scan;