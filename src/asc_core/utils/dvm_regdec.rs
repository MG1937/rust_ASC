use crate::asc_core::models::dvm_opcode::Format;
use crate::asc_core::models::dvm_opcode::DvmOpcode;

// https://cs.android.com/android/platform/superproject/+/android-latest-release:art/libdexfile/dex/dex_instruction-inl.h

pub fn get_index(bytecode_flow: &[u8], dvm_op: &DvmOpcode, pc: usize) -> u32 {
    let start = pc + 2; // index must in pos 2 of bytecode
    if dvm_op.fmt == Format::k31c {
        // op vAA, thing@BBBBBBBB
        return (bytecode_flow[start] as u32)
            | ((bytecode_flow[start + 1] as u32) << 8)
            | ((bytecode_flow[start + 2] as u32) << 16)
            | ((bytecode_flow[start + 3] as u32) << 24);
    }
    (bytecode_flow[start] as u32) | ((bytecode_flow[start + 1] as u32) << 8)
}

pub fn set_index(bytecode_flow: &mut [u8], pc: usize, new_idx: u32, dvm_op: &DvmOpcode) {
    let start = pc + 2; // index must in pos 2 of bytecode
    if dvm_op.fmt == Format::k31c {
        bytecode_flow[start] = (new_idx & 0xFF) as u8;
        bytecode_flow[start + 1] = ((new_idx >> 8) & 0xFF) as u8;
        bytecode_flow[start + 2] = ((new_idx >> 16) & 0xFF) as u8;
        bytecode_flow[start + 3] = ((new_idx >> 24) & 0xFF) as u8;
    } else {
        bytecode_flow[start] = (new_idx & 0xFF) as u8;
        bytecode_flow[start + 1] = ((new_idx >> 8) & 0xFF) as u8;
    }
}

pub fn fetch16(bytecode_flow: &[u8], pc: usize, word_offset: usize) -> u16 {
    let start = pc + word_offset * 2;
    u16::from_le_bytes([bytecode_flow[start], bytecode_flow[start + 1]])
}

pub fn get_vreg_a(bytecode_flow: &[u8], pc: usize, dvm_op: &DvmOpcode) -> Option<u32> {
    let fmt = &dvm_op.fmt;
    let w0 = fetch16(bytecode_flow, pc, 0);

    if matches!(fmt, Format::k10t | Format::k10x | Format::k11x | Format::k21c | Format::k21h
        | Format::k21s | Format::k21t | Format::k22b | Format::k22x | Format::k23x
        | Format::k31c | Format::k31i | Format::k31t | Format::k3rc | Format::k51l | Format::k4rcc) {
        return Some((w0 >> 8) as u32);
    }
    if matches!(fmt, Format::k11n | Format::k12x | Format::k22c | Format::k22s | Format::k22t) {
        return Some(((w0 >> 8) & 0x0f) as u32);
    }
    if *fmt == Format::k20t {
        let val = i16::from_le_bytes([bytecode_flow[pc + 2], bytecode_flow[pc + 3]]);
        return Some(val as u32);
    }
    if *fmt == Format::k30t {
        let val = i32::from_le_bytes([
            bytecode_flow[pc + 2], bytecode_flow[pc + 3],
            bytecode_flow[pc + 4], bytecode_flow[pc + 5],
        ]);
        return Some(val as u32);
    }
    if *fmt == Format::k32x {
        return Some(fetch16(bytecode_flow, pc, 1) as u32);
    }
    if matches!(fmt, Format::k35c | Format::k45cc) {
        return Some((w0 >> 12) as u32);
    }
    None
}

pub fn get_vreg_b(bytecode_flow: &[u8], pc: usize, dvm_op: &DvmOpcode) -> Option<u64> {
    let fmt = &dvm_op.fmt;
    let w0 = fetch16(bytecode_flow, pc, 0);

    if matches!(fmt, Format::k12x | Format::k22c | Format::k22s | Format::k22t) {
        return Some((w0 >> 12) as u64);
    }
    if *fmt == Format::k11n {
        let val = (w0 >> 12) as i32;
        return Some(if val > 7 { (val - 16) as u64 } else { val as u64 });
    }
    if matches!(fmt, Format::k21c | Format::k21h | Format::k21s | Format::k21t | Format::k22b
        | Format::k22x | Format::k23x | Format::k35c | Format::k3rc | Format::k45cc | Format::k4rcc) {
        return Some(fetch16(bytecode_flow, pc, 1) as u64);
    }
    if matches!(fmt, Format::k31c | Format::k31i | Format::k31t) {
        let val = u32::from_le_bytes([
            bytecode_flow[pc + 2], bytecode_flow[pc + 3],
            bytecode_flow[pc + 4], bytecode_flow[pc + 5],
        ]);
        return Some(val as u64);
    }
    if *fmt == Format::k32x {
        return Some(fetch16(bytecode_flow, pc, 2) as u64);
    }
    if *fmt == Format::k51l {
        let val = u64::from_le_bytes([
            bytecode_flow[pc + 2], bytecode_flow[pc + 3],
            bytecode_flow[pc + 4], bytecode_flow[pc + 5],
            bytecode_flow[pc + 6], bytecode_flow[pc + 7],
            bytecode_flow[pc + 8], bytecode_flow[pc + 9],
        ]);
        return Some(val);
    }
    None
}

pub fn get_vreg_c(bytecode_flow: &[u8], pc: usize, dvm_op: &DvmOpcode) -> Option<u32> {
    let fmt = &dvm_op.fmt;
    if matches!(fmt, Format::k22b | Format::k23x) {
        return Some((fetch16(bytecode_flow, pc, 1) >> 8) as u32);
    }
    if matches!(fmt, Format::k22c | Format::k22s | Format::k22t) {
        return Some(fetch16(bytecode_flow, pc, 1) as u32);
    }
    if matches!(fmt, Format::k35c | Format::k45cc) {
        return Some((fetch16(bytecode_flow, pc, 2) & 0x0f) as u32);
    }
    if matches!(fmt, Format::k3rc | Format::k4rcc) {
        return Some(fetch16(bytecode_flow, pc, 2) as u32);
    }
    None
}

pub fn get_vreg_h(bytecode_flow: &[u8], pc: usize, dvm_op: &DvmOpcode) -> Option<u32> {
    if matches!(dvm_op.fmt, Format::k45cc | Format::k4rcc) {
        return Some(fetch16(bytecode_flow, pc, 3) as u32);
    }
    None
}