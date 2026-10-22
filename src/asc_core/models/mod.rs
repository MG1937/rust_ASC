//! DEX/Dalvik model constants.
//!
//! `dvm_opcode` holds opcode tables and verifier flags; it is stable data, not
//! business logic.
//!
//! Rules:
//! - Add opcodes/verifier bits only to this table; do not hardcode magic numbers
//!   in locators or scanners.
//! - This is a leaf module and must not depend on other business modules.
pub mod dvm_opcode;