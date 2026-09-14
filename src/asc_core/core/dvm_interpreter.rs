// Auth: MG1937

// https://source.android.com/docs/core/runtime/instruction-formats

use crate::asc_core::models::dvm_opcode;
use crate::asc_core::models::dvm_opcode::DvmOpcode;

pub const WORD: usize = 2;

pub trait DvmHandler {
    // basic handler trait
    fn should_break(&self) -> bool;
    fn call(&mut self, bvmopcode: &DvmOpcode, pc: usize, result: Option<u32>) -> Option<u32>;
}

pub struct DvmInterpreter {
    // handlers
    pub handlers: Vec<Box<dyn DvmHandler>>,
}

impl DvmInterpreter {
    pub fn new() -> Self {
        DvmInterpreter { handlers: Vec::new() }
    }

    pub fn addHandler(&mut self, handler: Box<dyn DvmHandler>) {
        self.handlers.push(handler);
    }

    pub fn interpret(&mut self, bytecode: &mut Vec<u8>) {
        // only own bytecode's copy
        // only handler can operate origin bytecode flow
        let flow_len = bytecode.len();
        let mut pc = 0;
        while flow_len > pc {
            let opcode = bytecode[pc];
            if !dvm_opcode::opcodes.contains_key(&opcode) {
                // We reached a payload data section (like array-data or switch-data)
                // This should only happen if the handler failed to bound the PC correctly,
                // or if we actually hit the data block. We should break here.
                break;
            }

            let dvmopcode = &dvm_opcode::opcodes[&opcode];
            let mut handler_result: Option<u32> = None;

            // Allow handlers to signal early termination
            for handler in self.handlers.iter_mut() {
                handler_result = handler.call(dvmopcode, pc, handler_result);
                if handler.should_break() {
                    break;
                }
            }

            // If any handler signaled a break, we terminate the interpretation loop
            if self.handlers.iter().any(|h| h.should_break()) {
                break;
            }

            pc += dvmopcode.oplen as usize * WORD;
        }
    }
}