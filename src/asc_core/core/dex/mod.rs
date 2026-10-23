//! DEX rebuild sub-stages.
//!
//! Boundaries:
//! - `dex_constructor`: hollow the target class and its dependencies.
//! - `dex_remapper`: remap original indices into compact new tables.
//! - `dex_builder`: emit DEX bytes from the remapped tables.
//! - `dex_manager`: wires the stages and is the only public entry point.
//!
//! Rules:
//! - Stages exchange data only through `DexManager`; the builder must not read
//!   the original APK/ZIP.
//! - All index mapping goes through `dex_remapper`; do not add another mapping
//!   implementation in the builder or constructor.
//! - Reuse layout constants and readers from `utils::structs`/`utils::tinydex`;
//!   do not hardcode a second copy of the layout here.
pub mod dex_builder;
pub mod dex_constructor;
pub mod dex_manager;
pub mod dex_remapper;