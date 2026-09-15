// Auth: MG1937

pub const DVM_OPCODE_TEMPLATE: &str = r#"// Auth: MG1937

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
{opcodes}        m
    };
}
"#;
