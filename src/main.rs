use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::time::Instant;

mod asc_core;
mod asc_client;

use asc_client::asc_handler::AscHandler;
use asc_core::findrefs::findrefs_manager::FindRefInput;
use asc_core::findrefs::locator::field_locator::FieldFind;
use asc_core::findrefs::locator::method_locator::MethodFind;

fn format_class_name(name: &str) -> String {
    if name.is_empty() {
        panic!("Class name cannot be empty");
    }
    if name.starts_with("L") && name.ends_with(";") && name.contains("/") {
        return name.to_string();
    }
    let mut name = name.replace(".", "/");
    if !name.starts_with("L") {
        name = format!("L{}", name);
    }
    if !name.ends_with(";") {
        name = format!("{};", name);
    }
    name
}

fn normalize_class_query(name: Option<&str>, fuzzy: bool) -> Option<String> {
    match name {
        None => None,
        Some(n) => {
            if fuzzy {
                if n.contains(".") && !n.contains("/") {
                    return Some(n.replace(".", "/"));
                }
                Some(n.to_string())
            } else {
                Some(format_class_name(n))
            }
        }
    }
}

fn build_member_find(key: &str, clz: Option<&str>, clz_fuzzy: bool, name: Option<&str>) -> FindRefInput {
    let clz = clz.and_then(|c| if c.is_empty() { None } else { Some(c) });
    let name = name.and_then(|n| if n.is_empty() { None } else { Some(n) });

    if clz.is_none() && name.is_none() {
        panic!("{} query needs at least one of class or {} name", key, key);
    }

    let class_pair = clz.map(|c| {
        let normalized = normalize_class_query(Some(c), clz_fuzzy).unwrap();
        (normalized, !clz_fuzzy)
    });

    match key {
        "method" => FindRefInput {
            string: None,
            type_: None,
            method: Some(MethodFind::new(class_pair, name.map(|n| n.to_string()))),
            field: None,
        },
        "field" => FindRefInput {
            string: None,
            type_: None,
            method: None,
            field: Some(FieldFind::new(class_pair, name.map(|n| n.to_string()))),
        },
        _ => panic!("Unknown member type: {}", key),
    }
}

fn get_find_query(args: &CliArgs) -> (String, FindRefInput) {
    match args.find_type.as_deref() {
        Some("string") => (
            "string".to_string(),
            FindRefInput {
                string: args.value.as_deref().map(|s| s.to_string()),
                type_: None,
                method: None,
                field: None,
            },
        ),
        Some("type") => (
            "type".to_string(),
            FindRefInput {
                string: None,
                type_: args.value.as_deref().map(|s| s.to_string()),
                method: None,
                field: None,
            },
        ),
        Some("method") => {
            let find = build_member_find("method", args.class_name.as_deref(), args.fuzzy_class, args.name.as_deref());
            ("method".to_string(), find)
        }
        Some("field") => {
            let find = build_member_find("field", args.class_name.as_deref(), args.fuzzy_class, args.name.as_deref());
            ("field".to_string(), find)
        }
        _ => panic!("Unknown find type"),
    }
}

struct CliArgs {
    command: String,
    apk_path: String,
    debug: bool,
    threads: usize,
    output: Option<String>,
    dalvik_class: Option<String>,
    find_type: Option<String>,
    value: Option<String>,
    name: Option<String>,
    class_name: Option<String>,
    fuzzy_class: bool,
}

fn parse_args() -> CliArgs {
    let raw: Vec<String> = env::args().collect();
    if raw.len() < 2 {
        eprintln!("Usage: rust_ASC <command> [options]");
        std::process::exit(1);
    }

    let mut cli = CliArgs {
        command: String::new(),
        apk_path: String::new(),
        debug: false,
        threads: 8,
        output: None,
        dalvik_class: None,
        find_type: None,
        value: None,
        name: None,
        class_name: None,
        fuzzy_class: false,
    };

    // Collect positional args in order, skipping flags
    let mut positional: Vec<String> = Vec::new();

    let mut i = 1;
    while i < raw.len() {
        let arg = &raw[i];
        match arg.as_str() {
            "--debug" => { cli.debug = true; i += 1; }
            "--threads" | "--thread" => {
                cli.threads = raw.get(i+1).and_then(|v| v.parse().ok()).unwrap_or(8);
                i += 2;
            }
            "-o" | "--output" => {
                cli.output = raw.get(i+1).cloned();
                i += 2;
            }
            "--fuzzy-class" => { cli.fuzzy_class = true; i += 1; }
            "--class" => {
                cli.class_name = raw.get(i+1).cloned();
                i += 2;
            }
            _ => {
                if arg.starts_with("-") {
                    i += 1; // unknown flag, skip
                } else {
                    positional.push(arg.clone());
                    i += 1;
                }
            }
        }
    }

    // Now parse positional args
    if positional.is_empty() {
        eprintln!("Usage: rust_ASC <command> [options]");
        std::process::exit(1);
    }

    cli.command = positional[0].clone();
    match cli.command.as_str() {
        "getclass" => {
            if positional.len() > 1 { cli.apk_path = positional[1].clone(); }
            if positional.len() > 2 { cli.dalvik_class = Some(positional[2].clone()); }
        }
        "findrefs" => {
            if positional.len() > 1 { cli.apk_path = positional[1].clone(); }
            if positional.len() > 2 { cli.find_type = Some(positional[2].clone()); }
            if positional.len() > 3 { cli.value = Some(positional[3].clone()); }
            // For method/field, the "name" is the method/field name (stored in value)
            // --class and --fuzzy-class are already parsed above
        }
        _ => {
            eprintln!("Unknown command: {}", cli.command);
            std::process::exit(1);
        }
    }

    cli
}

fn handle_getclass(args: &CliArgs) {
    use crate::asc_client::apk_handler::ApkHandler;

    let t_start = Instant::now();
    let dalvik_class = format_class_name(args.dalvik_class.as_deref().unwrap());
    let apk_handler = ApkHandler::new(&args.apk_path, args.debug, args.threads);
    let hit = apk_handler.get_class_dex(&dalvik_class);

    let hit = match hit {
        Some(h) => h,
        None => {
            eprintln!("Error: Class {} not found in APK.", dalvik_class);
            std::process::exit(1);
        }
    };

    let (_dex_name, dex_buf) = hit;
    if args.debug {
        let t_hit_end = Instant::now();
        let _ = t_hit_end;
    }

    use crate::asc_client::asc_handler::AscHandler;
    let source_code = AscHandler::new(args.debug).getclass(&dex_buf, &dalvik_class);
    let t_end = Instant::now();

    if args.debug {
        println!("[DEBUG] Total Execution Time: {} us", t_end.duration_since(t_start).as_micros());
    }

    if let Some(ref output) = args.output {
        let mut content = source_code.clone();
        if !content.ends_with("\n") {
            content.push('\n');
        }
        fs::write(output, content).unwrap();
    }
    print!("{}", source_code);
}

fn handle_findrefs(args: &CliArgs) {
    use crate::asc_client::apk_handler::ApkHandler;

    let t_start = Instant::now();
    let apk_handler = ApkHandler::new(&args.apk_path, args.debug, args.threads);
    let (_find_type, find) = get_find_query(args);

    let output_fp = args.output.as_ref().map(|path| {
        fs::File::create(path).unwrap()
    });

    let mut out: Box<dyn Write> = Box::new(io::stdout());
    let mut maybe_file: Option<fs::File> = None;

    for (_dex_name, lines) in apk_handler.for_each_findrefs(&_find_type, &find) {
        if lines.is_empty() {
            continue;
        }
        let text = lines.join("\n") + "\n";
        write!(out, "{}", text).unwrap();
        if let Some(ref fp) = output_fp {
            let mut fp = fp.try_clone().unwrap();
            write!(fp, "{}", text).unwrap();
        }
    }

    if args.debug {
        let t_end = Instant::now();
        println!("[DEBUG] Total Execution Time: {} us", t_end.duration_since(t_start).as_micros());
    }
}

fn main() {
    let args = parse_args();
    match args.command.as_str() {
        "getclass" => handle_getclass(&args),
        "findrefs" => handle_findrefs(&args),
        _ => {
            eprintln!("Usage: rust_ASC getclass|findrefs ...");
            std::process::exit(1);
        }
    }
}