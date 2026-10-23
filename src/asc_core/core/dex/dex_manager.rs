use std::collections::HashMap;
use std::time::Instant;
use std::path::Path;
use std::fs::File;
use std::io::Read;

use crate::asc_core::utils::tinydex::DEX;
use crate::asc_core::core::dvm_interpreter::DvmInterpreter;
use crate::asc_core::core::dvm_handlers::IndexHandler;
use crate::asc_core::core::dex::dex_remapper::DexIndexMapper;
use crate::asc_core::core::dex::dex_constructor::DexHollower;
use crate::asc_core::core::dex::dex_builder::DexBuilder;

// Auth: MG1937
// this part gen by LLM, I already build the infra, let LLM arrange this

pub struct DexManager {
    pub dex_path: Option<String>,
    pub dex_name: String,
    pub dexraw: Vec<u8>,
    pub debug: bool,
    pub dex: Option<DEX>,
}

impl DexManager {
    pub fn new(dex_element: &str, debug: bool) -> Self {
        let mut manager = DexManager {
            dex_path: None,
            dex_name: String::new(),
            dexraw: Vec::new(),
            debug,
            dex: None,
        };

        // Check if dex_element is a file path
        let path = Path::new(dex_element);
        if path.exists() {
            manager.dex_path = Some(dex_element.to_string());
            manager.dex_name = path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
        } else {
            // Assume it's a memory reference (we store the name only)
            manager.dex_name = dex_element.to_string();
        }

        manager._load_dex();
        manager
    }

    /// Create a DexManager from in-memory bytes
    pub fn from_bytes(bytes: Vec<u8>, debug: bool) -> Self {
        let mut manager = DexManager {
            dex_path: None,
            dex_name: "<memory>".to_string(),
            dexraw: bytes,
            debug,
            dex: None,
        };
        manager._load_dex();
        manager
    }

    fn _load_dex(&mut self) {
        let t_start = if self.debug { Some(Instant::now()) } else { None };

        if self.dexraw.is_empty() {
            if let Some(ref path_str) = self.dex_path {
                let mut f = File::open(path_str).expect("Failed to open DEX file");
                f.read_to_end(&mut self.dexraw).expect("Failed to read DEX file");
            }
        }

        let dex = DEX::parse(&self.dexraw, &self.dex_name);
        self.dex = Some(dex);

        if self.debug {
            let t_end = Instant::now();
            println!("[DEBUG] DexManager load_dex Time: {:.2} us", t_start.unwrap().elapsed().as_secs_f64() * 1000000.0);
        }
    }

    pub fn extract_and_rebuild(&mut self, dalvik_class_fmt: &str) -> Vec<u8> {
        let t_start = Instant::now();

        let dex_ref = self.dex.as_ref().unwrap();
        let mut clazz = dex_ref.get_class(dalvik_class_fmt)
            .expect(&format!("Class {} not found in DEX.", dalvik_class_fmt));

        let mut dvminterp = DvmInterpreter::new();
        dvminterp.addHandler(Box::new(IndexHandler::new()));
        dvminterp
            .getHandler_mut::<IndexHandler>()
            .expect("IndexHandler is not registered")
            .preregister_own_fields(clazz.fields());

        let mut modified_bytecodes: HashMap<u32, Vec<u8>> = HashMap::new();

        let t_setup_end = Instant::now();

        // 1. Execute interpreter to collect indices (optional modification step)
        let t_interp_start = Instant::now();
        for &method_idx in clazz.methods() {
            let method = dex_ref.get_method(method_idx);
            let mut bytecode_raw = method.bytecode();
            {
                let idx_handler = dvminterp
                    .getHandler_mut::<IndexHandler>()
                    .expect("IndexHandler is not registered");
                idx_handler.setBytecode(bytecode_raw.clone());
            }
            dvminterp.interpret(&mut bytecode_raw);
            let bytecode = dvminterp
                .getHandler_mut::<IndexHandler>()
                .expect("IndexHandler is not registered")
                .bytecode
                .clone();
            modified_bytecodes.insert(method_idx, bytecode);
        }
        let t_interp_end = Instant::now();

        // 2. Hollow out necessary data from original DEX
        let mut dexhlw = DexHollower::new(dex_ref, &self.dexraw, dalvik_class_fmt, self.debug);
        dexhlw.hollow();
        let t_hollow_end = Instant::now();

        // 3. Remap indices to create new continuous index tables
        let mapper = dvminterp
            .getHandler_mut::<IndexHandler>()
            .expect("IndexHandler is not registered")
            .getMapper()
            .clone();
        let mut indexmapper = DexIndexMapper::new(mapper, dex_ref, &self.dexraw);
        indexmapper.set_class(&mut clazz);

        // Clone the hollower's read-only data to avoid borrow conflict with mutable code_item_metadata_hlws
        let hlw_strs = dexhlw.hlw_strs.clone();
        let hlw_types = dexhlw.hlw_types.clone();
        let hlw_fields = dexhlw.hlw_fields.clone();
        let hlw_methods = dexhlw.hlw_methods.clone();
        let clz_def_hlw_types = dexhlw.clz_def_hlw_types.clone();
        let clz_def_hlw_strs = dexhlw.clz_def_hlw_strs.clone();
        let ifs_list_hlw_types = dexhlw.ifs_list_hlw_types.clone();

        indexmapper.handle(
            &hlw_strs,
            &hlw_types,
            &hlw_fields,
            &hlw_methods,
            &clz_def_hlw_types,
            &clz_def_hlw_strs,
            &ifs_list_hlw_types,
            &mut dexhlw.code_item_metadata_hlws,
        );
        let t_remap_end = Instant::now();

        // 4. Build the new DEX
        let mut builder = DexBuilder::new(&indexmapper, &dexhlw, &modified_bytecodes, self.debug);
        let new_dex_bytes = builder.build();
        let t_build_end = Instant::now();

        if self.debug {
            println!("[DEBUG] Setup Time: {:.2} us", (t_setup_end - t_start).as_secs_f64() * 1000000.0);
            println!("[DEBUG] Interpreter Time: {:.2} us", (t_interp_end - t_interp_start).as_secs_f64() * 1000000.0);
            println!("[DEBUG] Hollower Time: {:.2} us", (t_hollow_end - t_interp_end).as_secs_f64() * 1000000.0);
            println!("[DEBUG] Remapper Time: {:.2} us", (t_remap_end - t_hollow_end).as_secs_f64() * 1000000.0);
            println!("[DEBUG] Builder Time: {:.2} us", (t_build_end - t_remap_end).as_secs_f64() * 1000000.0);
            println!("[DEBUG] Total Extraction Time: {:.2} us", (t_build_end - t_start).as_secs_f64() * 1000000.0);
        }

        new_dex_bytes
    }
}
