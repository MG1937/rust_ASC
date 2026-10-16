// Little-endian fixed-width DEX record readers shared by the parser and findrefs locators.

#![allow(non_camel_case_types)]

pub struct _STRUCT_I;
impl _STRUCT_I {
    #[inline(always)]
    pub fn unpack_from(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }

    #[inline(always)]
    pub fn try_unpack_from(buf: &[u8], off: usize) -> Option<u32> {
        Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
    }
}

pub struct _STRUCT_H;
impl _STRUCT_H {
    #[inline(always)]
    pub fn unpack_from(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([buf[off], buf[off + 1]])
    }
}

pub struct _STRUCT_III;
impl _STRUCT_III {
    #[inline(always)]
    pub fn unpack_from(buf: &[u8], off: usize) -> (u32, u32, u32) {
        (
            _STRUCT_I::unpack_from(buf, off),
            _STRUCT_I::unpack_from(buf, off + 4),
            _STRUCT_I::unpack_from(buf, off + 8),
        )
    }
}

pub struct _STRUCT_HHI;
impl _STRUCT_HHI {
    #[inline(always)]
    pub fn unpack_from(buf: &[u8], off: usize) -> (u16, u16, u32) {
        (
            _STRUCT_H::unpack_from(buf, off),
            _STRUCT_H::unpack_from(buf, off + 2),
            _STRUCT_I::unpack_from(buf, off + 4),
        )
    }
}

pub struct _STRUCT_HHHHII;
impl _STRUCT_HHHHII {
    #[inline(always)]
    pub fn unpack_from(buf: &[u8], off: usize) -> (u16, u16, u16, u16, u32, u32) {
        (
            _STRUCT_H::unpack_from(buf, off),
            _STRUCT_H::unpack_from(buf, off + 2),
            _STRUCT_H::unpack_from(buf, off + 4),
            _STRUCT_H::unpack_from(buf, off + 6),
            _STRUCT_I::unpack_from(buf, off + 8),
            _STRUCT_I::unpack_from(buf, off + 12),
        )
    }
}
