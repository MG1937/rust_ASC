// Auth: MG1937

// dvm_handlers response to deal how to handle bytecode

use std::collections::HashMap;

use crate::asc_core::core::dvm_interpreter::DvmHandler;
use crate::asc_core::models::dvm_opcode::DvmOpcode;
use crate::asc_core::models::dvm_opcode::IndexFlag;
use crate::asc_core::models::dvm_opcode::VerifyFlag;
use crate::asc_core::utils::dvm_regdec::get_index;
use crate::asc_core::utils::dvm_regdec::get_vreg_b;
use crate::asc_core::utils::dvm_regdec::set_index;

pub struct IndexHandler {
    pub should_break: bool,
    pub bytecode: Vec<u8>,
    pub pc_bound: usize,
    pub mapper: HashMap<String, HashMap<u32, u32>>,
    pub reverse_mapper: HashMap<String, HashMap<u32, u32>>,
}

impl IndexHandler {
    pub fn new() -> Self {
        let mut mapper = HashMap::new();
        mapper.insert("CLASS".to_string(), HashMap::new());
        mapper.insert("METHOD".to_string(), HashMap::new());
        mapper.insert("FIELD".to_string(), HashMap::new());
        mapper.insert("TYPE".to_string(), HashMap::new());
        mapper.insert("STRING".to_string(), HashMap::new());

        let mut reverse_mapper = HashMap::new();
        reverse_mapper.insert("CLASS".to_string(), HashMap::new());
        reverse_mapper.insert("METHOD".to_string(), HashMap::new());
        reverse_mapper.insert("FIELD".to_string(), HashMap::new());
        reverse_mapper.insert("TYPE".to_string(), HashMap::new());
        reverse_mapper.insert("STRING".to_string(), HashMap::new());

        IndexHandler {
            should_break: false,
            bytecode: Vec::new(),
            pc_bound: 0xffff,
            mapper,
            reverse_mapper,
        }
    }

    pub fn mapIndex(&mut self, origin_idx: u32, idx_type: &str) -> u32 {
        let rev = self.reverse_mapper.get_mut(idx_type).unwrap();
        if !rev.contains_key(&origin_idx) {
            let fwd = self.mapper.get_mut(idx_type).unwrap();
            let new_idx = fwd.len() as u32;
            fwd.insert(new_idx, origin_idx);
            rev.insert(origin_idx, new_idx);
            return new_idx;
        }
        rev[&origin_idx]
    }

    pub fn getMapper(&self) -> &HashMap<String, HashMap<u32, u32>> {
        &self.mapper
    }

    pub fn setBytecode(&mut self, bytecode: Vec<u8>) {
        self.bytecode = bytecode;
        self.pc_bound = 0xffff;
        self.should_break = false;
    }
}

impl DvmHandler for IndexHandler {
    fn should_break(&self) -> bool {
        self.should_break
    }

    // should call before BytecodeHandler
    fn call(&mut self, dvmopcode: &DvmOpcode, pc: usize, _result: Option<u32>) -> Option<u32> {
        let idx_fmt = &dvmopcode.idx;

        if self.pc_bound <= pc {
            // Reached the data block boundary (e.g. switch data, array data)
            self.should_break = true;
            return None;
        }

        if *idx_fmt == IndexFlag::kIndexNone {
            if dvmopcode.vflag & VerifyFlag::kVerifySwitchTargets != 0
                || dvmopcode.vflag & VerifyFlag::kVerifyArrayData != 0
            {
                // packed-switch/sparse-switch/fill-array-data issue
                // They all use +BBBBBBBB relative offset to data payloads at the end of the method
                // The offset is in 16-bit code units (so we multiply by 2 for byte offset)
                let bound = pc + (get_vreg_b(&self.bytecode, pc, dvmopcode).unwrap_or(0) as usize) * 2;
                self.pc_bound = if bound < self.pc_bound { bound } else { self.pc_bound };
                // println!("pc boundary >> {}", bound);
            }
            return None; // dont care
        }

        let origin_idx = get_index(&self.bytecode, dvmopcode, pc);
        let mut new_idx = origin_idx;

        let idx_type = match idx_fmt {
            IndexFlag::kIndexTypeRef => Some("TYPE"),
            IndexFlag::kIndexStringRef => Some("STRING"),
            IndexFlag::kIndexMethodRef => Some("METHOD"),
            IndexFlag::kIndexFieldRef => Some("FIELD"),
            _ => None,
        };
        if let Some(it) = idx_type {
            new_idx = self.mapIndex(origin_idx, it);
        }

        if new_idx != origin_idx {
            set_index(&mut self.bytecode, pc, new_idx, dvmopcode);
        }

        Some(new_idx)
    }
}