//! Scanners: map already-located index sets to code-item offsets or class-def
//! results.
//!
//! Contract:
//! - `CodeItemScanner` receives a built `InsnLocator` plus target index sets; it
//!   does not build indices and does not format output.
//! - `ClassDefItemScanner` handles extends/impl class-def scans only; the sole
//!   trigger is `FindRefManager::find_ref`. Do not call it elsewhere.
//! - No I/O, no APK/ZIP, no CLI output.
//!
//! Layering warning:
//! - `method_id_scan` is legacy: it renders method listings and does not belong
//!   to findrefs. New listing features must go to `asc_client/apk`'s
//!   `dex_reader`; keep its entry point unchanged when it is migrated.
//! - Do not add a second implementation of the same scan (e.g. scanning bytes in
//!   the manager instead of using a scanner).
pub mod class_def_item_scan;
pub mod code_item_scan;
pub mod method_id_scan;
