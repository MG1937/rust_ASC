//! Index locators.
//!
//! Each locator owns exactly one index and follows the same contract
//! (aligned with Python):
//! - Lazy `parsed` flag; `locate()` returns an index set and is read-only, with
//!   no I/O and no global state.
//! - Dependencies are injected by the manager (string/type locators); locators
//!   must not construct each other.
//!
//! Known deviation from Python: Python's `locate()` calls `_build_map()` itself;
//! the current Rust implementation pre-builds in `find_ref` and `locate` does not
//! self-build. This is legacy debt and must not spread.
//!
//! Forbidden:
//! - A parallel query path such as `locate_unindexed`. A query must have exactly
//!   one matching implementation: either everything goes through `locate`, or a
//!   merge leaves only one path. Two coexisting paths are not allowed.
//! - Exposing internal map/CSR arrays as `pub` for external direct access.
//! - Duplicating opcode scanning or string decoding inside a locator.
pub mod base_locator;
pub mod field_locator;
pub mod insn_locator;
pub mod method_locator;
pub mod string_locator;
pub mod type_locator;