use crate::asc_core::findrefs::locator::type_locator::TypeLocator;
use crate::asc_core::utils::structs::_STRUCT_I;

pub struct ClassDefItemScanner<'a, 'b> {
    pub class_def_item_size: u32,
    pub submem: &'a [u8],
    pub type_locator: &'b TypeLocator<'a>,
}

impl<'a, 'b> ClassDefItemScanner<'a, 'b> {
    pub fn new(type_locator: &'b TypeLocator<'a>) -> Self {
        let class_def_item_offset = type_locator.base.dex.header.classes.0;
        let class_def_item_size = type_locator.base.dex.header.classes.1;
        let buf = type_locator.base.buf;
        let start = class_def_item_offset as usize;
        let end = start
            .saturating_add(0x20 * class_def_item_size as usize)
            .min(buf.len());
        let submem = buf.get(start..end).unwrap_or(&[]);
        ClassDefItemScanner {
            class_def_item_size,
            submem,
            type_locator,
        }
    }

    pub fn scan_extends(&self, target_clz: &str) -> Vec<u32> {
        let target_type_idx = self.type_locator._find_type_idx_precisely(target_clz);
        let mut ret: Vec<u32> = Vec::new();
        if target_type_idx == -1 {
            return ret;
        }

        let needle = (target_type_idx as u32).to_le_bytes();
        let mut pos: usize = 0;
        while let Some(found) = memchr::memmem::find(&self.submem[pos..], &needle) {
            let match_start = pos + found;
            pos = match_start + needle.len();
            // superclass idx - 0x8 should goto start offset of class_def_item
            let Some(class_def_off) = match_start.checked_sub(0x8) else {
                continue;
            };
            if class_def_off & 0x1f != 0 {
                // check for 0x20 alignment
                continue;
            }
            if class_def_off + 4 > self.submem.len() {
                continue;
            }
            ret.push(_STRUCT_I::unpack_from(self.submem, class_def_off));
        }
        ret
    }

    pub fn scan_implements(&self, target_clz: &str) -> Vec<u32> {
        let target_type_idx = self.type_locator._find_type_idx_precisely(target_clz);
        let mut ret: Vec<u32> = Vec::new();
        if target_type_idx == -1 {
            return ret;
        }

        // interfaces_off field offset inside a 0x20 class_def_item = 3 * 0x4
        // https://source.android.com/docs/core/runtime/dex-format#class-def-item
        for class_index in 0..self.class_def_item_size {
            let class_def_off = class_index as usize * 0x20;
            if class_def_off + 0x10 > self.submem.len() {
                break;
            }
            if _STRUCT_I::unpack_from(self.submem, class_def_off + 3 * 0x4) == 0 {
                continue;
            }
            let mut clazz = self.type_locator.base.dex.get_class_by_idx(class_index);
            if clazz
                .interface_type_ids()
                .contains(&(target_type_idx as u16))
            {
                ret.push(clazz.class_idx);
            }
        }
        ret
    }
}
