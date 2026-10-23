// Auth: MG1937

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use std::collections::HashMap;

pub struct VerifyFlag;

impl VerifyFlag {
    pub const kVerifyNothing: u32 = 0;
    pub const kVerifyRegA: u32 = 1;
    pub const kVerifyRegB: u32 = 2;
    pub const kVerifyRegAWide: u32 = 4;
    pub const kVerifyRegBWide: u32 = 8;
    pub const kVerifyRegBString: u32 = 16;
    pub const kVerifyRegBType: u32 = 32;
    pub const kVerifyRegCType: u32 = 64;
    pub const kVerifyRegBNewInstance: u32 = 128;
    pub const kVerifyRegCNewArray: u32 = 256;
    pub const kVerifyRegBFilledNewArray: u32 = 512;
    pub const kVerifyVarArg: u32 = 1024;
    pub const kVerifyVarArgRange: u32 = 2048;
    pub const kVerifyArrayData: u32 = 4096;
    pub const kVerifyBranchTarget: u32 = 8192;
    pub const kVerifySwitchTargets: u32 = 16384;
    pub const kVerifyRegC: u32 = 32768;
    pub const kVerifyRegCWide: u32 = 65536;
    pub const kVerifyError: u32 = 131072;
    pub const kVerifyRegCField: u32 = 262144;
    pub const kVerifyRegBField: u32 = 524288;
    pub const kVerifyRegBMethod: u32 = 1048576;
    pub const kVerifyVarArgNonZero: u32 = 2097152;
    pub const kVerifyVarArgRangeNonZero: u32 = 4194304;
    pub const kVerifyRegHPrototype: u32 = 8388608;
    pub const kVerifyRegBCallSite: u32 = 16777216;
    pub const kVerifyRegBMethodHandle: u32 = 33554432;
    pub const kVerifyRegBPrototype: u32 = 67108864;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexFlag {
    kIndexNone,
    kIndexStringRef,
    kIndexTypeRef,
    kIndexUnknown,
    kIndexFieldRef,
    kIndexMethodRef,
    kIndexMethodAndProtoRef,
    kIndexCallSiteRef,
    kIndexMethodHandleRef,
    kIndexProtoRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    k10x,  // op
    k12x,  // op vA, vB
    k11n,  // op vA, #+B
    k11x,  // op vAA
    k10t,  // op +AA
    k20t,  // op +AAAA
    k22x,  // op vAA, vBBBB
    k21t,  // op vAA, +BBBB
    k21s,  // op vAA, #+BBBB
    k21h,  // op vAA, #+BBBB00000[00000000]
    k21c,  // op vAA, thing@BBBB
    k23x,  // op vAA, vBB, vCC
    k22b,  // op vAA, vBB, #+CC
    k22t,  // op vA, vB, +CCCC
    k22s,  // op vA, vB, #+CCCC
    k22c,  // op vA, vB, thing@CCCC
    k32x,  // op vAAAA, vBBBB
    k30t,  // op +AAAAAAAA
    k31t,  // op vAA, +BBBBBBBB
    k31i,  // op vAA, #+BBBBBBBB
    k31c,  // op vAA, thing@BBBBBBBB
    k35c,  // op {vC, vD, vE, vF, vG}, thing@BBBB (B: count, A: vG)
    k3rc,  // op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB
    k51l,  // op vAA, #+BBBBBBBBBBBBBBBB
    k45cc, // op {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH (A: count)
    k4rcc, // op {VCCCC .. v(CCCC+AA-1)}, meth@BBBB, proto@HHHH (AA: count)
}

pub struct DvmOpcode {
    pub name: &'static str,
    pub oplen: u32,
    pub fmt: Format,
    pub idx: IndexFlag,
    pub vflag: u32,
}

impl DvmOpcode {
    pub const fn new(name: &'static str, oplen: u32, fmt: Format, idx: IndexFlag, vflag: u32) -> Self {
        DvmOpcode { name, oplen, fmt, idx, vflag }
    }
}

lazy_static::lazy_static! {
    pub static ref opcodes: HashMap<u8, DvmOpcode> = {
        let mut m = HashMap::new();
        m.insert(0x00, DvmOpcode::new("nop", 1, Format::k10x, IndexFlag::kIndexNone, VerifyFlag::kVerifyNothing));
        m.insert(0x01, DvmOpcode::new("move", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x02, DvmOpcode::new("move/from16", 2, Format::k22x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x03, DvmOpcode::new("move/16", 3, Format::k32x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x04, DvmOpcode::new("move-wide", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0x05, DvmOpcode::new("move-wide/from16", 2, Format::k22x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0x06, DvmOpcode::new("move-wide/16", 3, Format::k32x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0x07, DvmOpcode::new("move-object", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x08, DvmOpcode::new("move-object/from16", 2, Format::k22x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x09, DvmOpcode::new("move-object/16", 3, Format::k32x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x0A, DvmOpcode::new("move-result", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x0B, DvmOpcode::new("move-result-wide", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide));
        m.insert(0x0C, DvmOpcode::new("move-result-object", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x0D, DvmOpcode::new("move-exception", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x0E, DvmOpcode::new("return-void", 1, Format::k10x, IndexFlag::kIndexNone, VerifyFlag::kVerifyNothing));
        m.insert(0x0F, DvmOpcode::new("return", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x10, DvmOpcode::new("return-wide", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide));
        m.insert(0x11, DvmOpcode::new("return-object", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x12, DvmOpcode::new("const/4", 1, Format::k11n, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x13, DvmOpcode::new("const/16", 2, Format::k21s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x14, DvmOpcode::new("const", 3, Format::k31i, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x15, DvmOpcode::new("const/high16", 2, Format::k21h, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x16, DvmOpcode::new("const-wide/16", 2, Format::k21s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide));
        m.insert(0x17, DvmOpcode::new("const-wide/32", 3, Format::k31i, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide));
        m.insert(0x18, DvmOpcode::new("const-wide", 5, Format::k51l, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide));
        m.insert(0x19, DvmOpcode::new("const-wide/high16", 2, Format::k21h, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide));
        m.insert(0x1A, DvmOpcode::new("const-string", 2, Format::k21c, IndexFlag::kIndexStringRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBString));
        m.insert(0x1B, DvmOpcode::new("const-string/jumbo", 3, Format::k31c, IndexFlag::kIndexStringRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBString));
        m.insert(0x1C, DvmOpcode::new("const-class", 2, Format::k21c, IndexFlag::kIndexTypeRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBType));
        m.insert(0x1D, DvmOpcode::new("monitor-enter", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x1E, DvmOpcode::new("monitor-exit", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x1F, DvmOpcode::new("check-cast", 2, Format::k21c, IndexFlag::kIndexTypeRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBType));
        m.insert(0x20, DvmOpcode::new("instance-of", 2, Format::k22c, IndexFlag::kIndexTypeRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCType));
        m.insert(0x21, DvmOpcode::new("array-length", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x22, DvmOpcode::new("new-instance", 2, Format::k21c, IndexFlag::kIndexTypeRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBNewInstance));
        m.insert(0x23, DvmOpcode::new("new-array", 2, Format::k22c, IndexFlag::kIndexTypeRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCNewArray));
        m.insert(0x24, DvmOpcode::new("filled-new-array", 3, Format::k35c, IndexFlag::kIndexTypeRef, VerifyFlag::kVerifyRegBFilledNewArray | VerifyFlag::kVerifyVarArg));
        m.insert(0x25, DvmOpcode::new("filled-new-array/range", 3, Format::k3rc, IndexFlag::kIndexTypeRef, VerifyFlag::kVerifyRegBFilledNewArray | VerifyFlag::kVerifyVarArgRange));
        m.insert(0x26, DvmOpcode::new("fill-array-data", 3, Format::k31t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyArrayData));
        m.insert(0x27, DvmOpcode::new("throw", 1, Format::k11x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA));
        m.insert(0x28, DvmOpcode::new("goto", 1, Format::k10t, IndexFlag::kIndexNone, VerifyFlag::kVerifyBranchTarget));
        m.insert(0x29, DvmOpcode::new("goto/16", 2, Format::k20t, IndexFlag::kIndexNone, VerifyFlag::kVerifyBranchTarget));
        m.insert(0x2A, DvmOpcode::new("goto/32", 3, Format::k30t, IndexFlag::kIndexNone, VerifyFlag::kVerifyBranchTarget));
        m.insert(0x2B, DvmOpcode::new("packed-switch", 3, Format::k31t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifySwitchTargets));
        m.insert(0x2C, DvmOpcode::new("sparse-switch", 3, Format::k31t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifySwitchTargets));
        m.insert(0x2D, DvmOpcode::new("cmpl-float", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x2E, DvmOpcode::new("cmpg-float", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x2F, DvmOpcode::new("cmpl-double", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0x30, DvmOpcode::new("cmpg-double", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0x31, DvmOpcode::new("cmp-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0x32, DvmOpcode::new("if-eq", 2, Format::k22t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x33, DvmOpcode::new("if-ne", 2, Format::k22t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x34, DvmOpcode::new("if-lt", 2, Format::k22t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x35, DvmOpcode::new("if-ge", 2, Format::k22t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x36, DvmOpcode::new("if-gt", 2, Format::k22t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x37, DvmOpcode::new("if-le", 2, Format::k22t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x38, DvmOpcode::new("if-eqz", 2, Format::k21t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x39, DvmOpcode::new("if-nez", 2, Format::k21t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x3A, DvmOpcode::new("if-ltz", 2, Format::k21t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x3B, DvmOpcode::new("if-gez", 2, Format::k21t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x3C, DvmOpcode::new("if-gtz", 2, Format::k21t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x3D, DvmOpcode::new("if-lez", 2, Format::k21t, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyBranchTarget));
        m.insert(0x44, DvmOpcode::new("aget", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x45, DvmOpcode::new("aget-wide", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x46, DvmOpcode::new("aget-object", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x47, DvmOpcode::new("aget-boolean", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x48, DvmOpcode::new("aget-byte", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x49, DvmOpcode::new("aget-char", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x4A, DvmOpcode::new("aget-short", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x4B, DvmOpcode::new("aput", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x4C, DvmOpcode::new("aput-wide", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x4D, DvmOpcode::new("aput-object", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x4E, DvmOpcode::new("aput-boolean", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x4F, DvmOpcode::new("aput-byte", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x50, DvmOpcode::new("aput-char", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x51, DvmOpcode::new("aput-short", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x52, DvmOpcode::new("iget", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x53, DvmOpcode::new("iget-wide", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x54, DvmOpcode::new("iget-object", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x55, DvmOpcode::new("iget-boolean", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x56, DvmOpcode::new("iget-byte", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x57, DvmOpcode::new("iget-char", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x58, DvmOpcode::new("iget-short", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x59, DvmOpcode::new("iput", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x5A, DvmOpcode::new("iput-wide", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x5B, DvmOpcode::new("iput-object", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x5C, DvmOpcode::new("iput-boolean", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x5D, DvmOpcode::new("iput-byte", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x5E, DvmOpcode::new("iput-char", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x5F, DvmOpcode::new("iput-short", 2, Format::k22c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegCField));
        m.insert(0x60, DvmOpcode::new("sget", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x61, DvmOpcode::new("sget-wide", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBField));
        m.insert(0x62, DvmOpcode::new("sget-object", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x63, DvmOpcode::new("sget-boolean", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x64, DvmOpcode::new("sget-byte", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x65, DvmOpcode::new("sget-char", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x66, DvmOpcode::new("sget-short", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x67, DvmOpcode::new("sput", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x68, DvmOpcode::new("sput-wide", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBField));
        m.insert(0x69, DvmOpcode::new("sput-object", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x6A, DvmOpcode::new("sput-boolean", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x6B, DvmOpcode::new("sput-byte", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x6C, DvmOpcode::new("sput-char", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x6D, DvmOpcode::new("sput-short", 2, Format::k21c, IndexFlag::kIndexFieldRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBField));
        m.insert(0x6E, DvmOpcode::new("invoke-virtual", 3, Format::k35c, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgNonZero));
        m.insert(0x6F, DvmOpcode::new("invoke-super", 3, Format::k35c, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgNonZero));
        m.insert(0x70, DvmOpcode::new("invoke-direct", 3, Format::k35c, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgNonZero));
        m.insert(0x71, DvmOpcode::new("invoke-static", 3, Format::k35c, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArg));
        m.insert(0x72, DvmOpcode::new("invoke-interface", 3, Format::k35c, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgNonZero));
        m.insert(0x74, DvmOpcode::new("invoke-virtual/range", 3, Format::k3rc, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgRangeNonZero));
        m.insert(0x75, DvmOpcode::new("invoke-super/range", 3, Format::k3rc, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgRangeNonZero));
        m.insert(0x76, DvmOpcode::new("invoke-direct/range", 3, Format::k3rc, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgRangeNonZero));
        m.insert(0x77, DvmOpcode::new("invoke-static/range", 3, Format::k3rc, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgRange));
        m.insert(0x78, DvmOpcode::new("invoke-interface/range", 3, Format::k3rc, IndexFlag::kIndexMethodRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgRangeNonZero));
        m.insert(0x7B, DvmOpcode::new("neg-int", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x7C, DvmOpcode::new("not-int", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x7D, DvmOpcode::new("neg-long", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0x7E, DvmOpcode::new("not-long", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0x7F, DvmOpcode::new("neg-float", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x80, DvmOpcode::new("neg-double", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0x81, DvmOpcode::new("int-to-long", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB));
        m.insert(0x82, DvmOpcode::new("int-to-float", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x83, DvmOpcode::new("int-to-double", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB));
        m.insert(0x84, DvmOpcode::new("long-to-int", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBWide));
        m.insert(0x85, DvmOpcode::new("long-to-float", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBWide));
        m.insert(0x86, DvmOpcode::new("long-to-double", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0x87, DvmOpcode::new("float-to-int", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x88, DvmOpcode::new("float-to-long", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB));
        m.insert(0x89, DvmOpcode::new("float-to-double", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB));
        m.insert(0x8A, DvmOpcode::new("double-to-int", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBWide));
        m.insert(0x8B, DvmOpcode::new("double-to-long", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0x8C, DvmOpcode::new("double-to-float", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBWide));
        m.insert(0x8D, DvmOpcode::new("int-to-byte", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x8E, DvmOpcode::new("int-to-char", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x8F, DvmOpcode::new("int-to-short", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0x90, DvmOpcode::new("add-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x91, DvmOpcode::new("sub-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x92, DvmOpcode::new("mul-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x93, DvmOpcode::new("div-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x94, DvmOpcode::new("rem-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x95, DvmOpcode::new("and-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x96, DvmOpcode::new("or-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x97, DvmOpcode::new("xor-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x98, DvmOpcode::new("shl-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x99, DvmOpcode::new("shr-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x9A, DvmOpcode::new("ushr-int", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0x9B, DvmOpcode::new("add-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0x9C, DvmOpcode::new("sub-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0x9D, DvmOpcode::new("mul-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0x9E, DvmOpcode::new("div-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0x9F, DvmOpcode::new("rem-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0xA0, DvmOpcode::new("and-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0xA1, DvmOpcode::new("or-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0xA2, DvmOpcode::new("xor-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0xA3, DvmOpcode::new("shl-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegC));
        m.insert(0xA4, DvmOpcode::new("shr-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegC));
        m.insert(0xA5, DvmOpcode::new("ushr-long", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegC));
        m.insert(0xA6, DvmOpcode::new("add-float", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0xA7, DvmOpcode::new("sub-float", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0xA8, DvmOpcode::new("mul-float", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0xA9, DvmOpcode::new("div-float", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0xAA, DvmOpcode::new("rem-float", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB | VerifyFlag::kVerifyRegC));
        m.insert(0xAB, DvmOpcode::new("add-double", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0xAC, DvmOpcode::new("sub-double", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0xAD, DvmOpcode::new("mul-double", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0xAE, DvmOpcode::new("div-double", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0xAF, DvmOpcode::new("rem-double", 2, Format::k23x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide | VerifyFlag::kVerifyRegCWide));
        m.insert(0xB0, DvmOpcode::new("add-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xB1, DvmOpcode::new("sub-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xB2, DvmOpcode::new("mul-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xB3, DvmOpcode::new("div-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xB4, DvmOpcode::new("rem-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xB5, DvmOpcode::new("and-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xB6, DvmOpcode::new("or-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xB7, DvmOpcode::new("xor-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xB8, DvmOpcode::new("shl-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xB9, DvmOpcode::new("shr-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xBA, DvmOpcode::new("ushr-int/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xBB, DvmOpcode::new("add-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xBC, DvmOpcode::new("sub-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xBD, DvmOpcode::new("mul-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xBE, DvmOpcode::new("div-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xBF, DvmOpcode::new("rem-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xC0, DvmOpcode::new("and-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xC1, DvmOpcode::new("or-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xC2, DvmOpcode::new("xor-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xC3, DvmOpcode::new("shl-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB));
        m.insert(0xC4, DvmOpcode::new("shr-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB));
        m.insert(0xC5, DvmOpcode::new("ushr-long/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegB));
        m.insert(0xC6, DvmOpcode::new("add-float/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xC7, DvmOpcode::new("sub-float/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xC8, DvmOpcode::new("mul-float/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xC9, DvmOpcode::new("div-float/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xCA, DvmOpcode::new("rem-float/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xCB, DvmOpcode::new("add-double/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xCC, DvmOpcode::new("sub-double/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xCD, DvmOpcode::new("mul-double/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xCE, DvmOpcode::new("div-double/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xCF, DvmOpcode::new("rem-double/2addr", 1, Format::k12x, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegAWide | VerifyFlag::kVerifyRegBWide));
        m.insert(0xD0, DvmOpcode::new("add-int/lit16", 2, Format::k22s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xD1, DvmOpcode::new("rsub-int", 2, Format::k22s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xD2, DvmOpcode::new("mul-int/lit16", 2, Format::k22s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xD3, DvmOpcode::new("div-int/lit16", 2, Format::k22s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xD4, DvmOpcode::new("rem-int/lit16", 2, Format::k22s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xD5, DvmOpcode::new("and-int/lit16", 2, Format::k22s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xD6, DvmOpcode::new("or-int/lit16", 2, Format::k22s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xD7, DvmOpcode::new("xor-int/lit16", 2, Format::k22s, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xD8, DvmOpcode::new("add-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xD9, DvmOpcode::new("rsub-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xDA, DvmOpcode::new("mul-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xDB, DvmOpcode::new("div-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xDC, DvmOpcode::new("rem-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xDD, DvmOpcode::new("and-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xDE, DvmOpcode::new("or-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xDF, DvmOpcode::new("xor-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xE0, DvmOpcode::new("shl-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xE1, DvmOpcode::new("shr-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xE2, DvmOpcode::new("ushr-int/lit8", 2, Format::k22b, IndexFlag::kIndexNone, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegB));
        m.insert(0xFA, DvmOpcode::new("invoke-polymorphic", 4, Format::k45cc, IndexFlag::kIndexMethodAndProtoRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgNonZero | VerifyFlag::kVerifyRegHPrototype));
        m.insert(0xFB, DvmOpcode::new("invoke-polymorphic/range", 4, Format::k4rcc, IndexFlag::kIndexMethodAndProtoRef, VerifyFlag::kVerifyRegBMethod | VerifyFlag::kVerifyVarArgRangeNonZero | VerifyFlag::kVerifyRegHPrototype));
        m.insert(0xFC, DvmOpcode::new("invoke-custom", 3, Format::k35c, IndexFlag::kIndexCallSiteRef, VerifyFlag::kVerifyRegBCallSite | VerifyFlag::kVerifyVarArg));
        m.insert(0xFD, DvmOpcode::new("invoke-custom/range", 3, Format::k3rc, IndexFlag::kIndexCallSiteRef, VerifyFlag::kVerifyRegBCallSite | VerifyFlag::kVerifyVarArgRange));
        m.insert(0xFE, DvmOpcode::new("const-method-handle", 2, Format::k21c, IndexFlag::kIndexMethodHandleRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBMethodHandle));
        m.insert(0xFF, DvmOpcode::new("const-method-type", 2, Format::k21c, IndexFlag::kIndexProtoRef, VerifyFlag::kVerifyRegA | VerifyFlag::kVerifyRegBPrototype));
        m
    };
}
