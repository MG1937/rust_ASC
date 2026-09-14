// Auth: MG1937

use crate::asc_core::utils::tinydex::DEX;
use std::time::Instant;

pub fn _debug_log(class_name: &str, stage: &str, t_start: Option<Instant>, count: Option<usize>, debug: bool) {
    if !debug {
        return;
    }
    let t_end = Instant::now();
    let elapsed_us = (t_end - t_start.unwrap()).as_secs_f64() * 1_000_000.0;
    match count {
        Some(c) => println!("[DEBUG] {}.{} Time: {:.2} us Count: {}", class_name, stage, elapsed_us, c),
        None => println!("[DEBUG] {}.{} Time: {:.2} us", class_name, stage, elapsed_us),
    }
}

pub struct BaseLocator<'a> {
    pub dex: &'a DEX,
    pub buf: &'a [u8],
    pub debug: bool,
}

impl<'a> BaseLocator<'a> {
    pub fn new(dex: &'a DEX) -> Self {
        BaseLocator {
            dex,
            buf: &dex.buf,
            debug: false,
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    pub fn _debug_log(&self, stage: &str, t_start: Option<Instant>, count: Option<usize>) {
        if !self.debug {
            return;
        }
        let t_end = Instant::now();
        let elapsed_us = (t_end - t_start.unwrap()).as_secs_f64() * 1_000_000.0;
        match count {
            Some(c) => println!("[DEBUG] BaseLocator.{} Time: {:.2} us Count: {}", stage, elapsed_us, c),
            None => println!("[DEBUG] BaseLocator.{} Time: {:.2} us", stage, elapsed_us),
        }
    }
}