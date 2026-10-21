use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::time::Instant;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use radguard::cli::{ExportOptions, ExportProgress, export_to_directory};

use crate::asc_client::apk_handler::ApkHandler;
use crate::asc_client::asc_handler::AscHandler;
use crate::asc_client::manifest_handler::get_manifest_xml;
use crate::asc_core::findrefs::findrefs_manager::FindRefInput;
use crate::asc_core::findrefs::locator::field_locator::FieldFind;
use crate::asc_core::findrefs::locator::method_locator::MethodFind;

fn _format_class_name(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("Class name cannot be empty".to_owned());
    }
    if name.starts_with('L') && name.ends_with(';') && name.contains('/') {
        return Ok(name.to_owned());
    }
    let mut name = name.replace('.', "/");
    if !name.starts_with('L') {
        name = format!("L{name}");
    }
    if !name.ends_with(';') {
        name.push(';');
    }
    Ok(name)
}

fn _normalize_class_query(name: Option<&str>, fuzzy: bool) -> Result<Option<String>, String> {
    let Some(name) = name else {
        return Ok(None);
    };
    if fuzzy {
        return Ok(Some(if name.contains('.') && !name.contains('/') {
            name.replace('.', "/")
        } else {
            name.to_owned()
        }));
    }
    _format_class_name(name).map(Some)
}

fn _build_member_find(
    key: &str,
    clz: Option<&str>,
    clz_fuzzy: bool,
    name: Option<&str>,
) -> Result<FindRefInput, String> {
    let clz = clz.filter(|value| !value.is_empty());
    let name = name.filter(|value| !value.is_empty());
    if clz.is_none() && name.is_none() {
        return Err(format!(
            "{key} query needs at least one of class or {key} name"
        ));
    }

    let class = _normalize_class_query(clz, clz_fuzzy)?.map(|value| (value, !clz_fuzzy));
    match key {
        "method" => Ok(FindRefInput {
            string: None,
            type_: None,
            method: Some(MethodFind::new(class, name.map(str::to_owned))),
            field: None,
        }),
        "field" => Ok(FindRefInput {
            string: None,
            type_: None,
            method: None,
            field: Some(FieldFind::new(class, name.map(str::to_owned))),
        }),
        _ => Err(format!("Unknown member type: {key}")),
    }
}

fn _get_find_query(args: &ArgMatches) -> Result<(String, FindRefInput), String> {
    let (find_type, find_args) = args
        .subcommand()
        .ok_or_else(|| "Unknown find type".to_owned())?;
    let find = match find_type {
        "string" => FindRefInput {
            string: find_args.get_one::<String>("value").cloned(),
            type_: None,
            method: None,
            field: None,
        },
        "type" => FindRefInput {
            string: None,
            type_: find_args.get_one::<String>("value").cloned(),
            method: None,
            field: None,
        },
        "method" | "field" => _build_member_find(
            find_type,
            find_args
                .get_one::<String>("class_name")
                .map(String::as_str),
            find_args.get_flag("fuzzy_class"),
            find_args.get_one::<String>("name").map(String::as_str),
        )?,
        _ => return Err(format!("Unknown find type: {find_type}")),
    };
    Ok((find_type.to_owned(), find))
}

fn write_text(path: &str, text: &str) -> Result<(), String> {
    let mut content = text.to_owned();
    if !content.ends_with('\n') {
        content.push('\n');
    }
    fs::write(path, content).map_err(|error| format!("cannot write {path}: {error}"))
}

fn _handle_getclass(args: &ArgMatches) -> Result<(), String> {
    let t_start = Instant::now();
    let apk_path = args.get_one::<String>("apk_path").unwrap();
    let dalvik_class = _format_class_name(args.get_one::<String>("dalvik_class").unwrap())?;
    let debug = args.get_flag("debug");
    let thread = _get_worker_count(args)?;

    let apk_handler = ApkHandler::new(apk_path, debug, thread);
    let (dex_name, dex_buf) = apk_handler
        .get_class_dex(&dalvik_class)
        .ok_or_else(|| format!("Class {dalvik_class} not found in APK."))?;
    let t_hit_end = Instant::now();
    let source_code = AscHandler::new(debug).getclass(&dex_buf, &dalvik_class);
    let t_end = Instant::now();

    if debug {
        println!("[DEBUG] Hit DEX: {dex_name}");
        println!(
            "[DEBUG] APK Scan Time: {:.2} us",
            (t_hit_end - t_start).as_secs_f64() * 1_000_000.0
        );
        println!(
            "[DEBUG] Total Execution Time: {:.2} us",
            (t_end - t_start).as_secs_f64() * 1_000_000.0
        );
        println!("{}", "-".repeat(50));
    }

    if let Some(output) = args.get_one::<String>("output") {
        write_text(output, &source_code)?;
    }
    println!("{source_code}");
    Ok(())
}

fn _handle_listclass(args: &ArgMatches) -> Result<(), String> {
    let t_start = Instant::now();
    let apk_path = args.get_one::<String>("apk_path").unwrap();
    let debug = args.get_flag("debug");
    let thread = _get_worker_count(args)?;
    let prefix = args.get_one::<String>("prefix").map(String::as_str);
    let handler = ApkHandler::new(apk_path, debug, thread);
    if let Some(output) = args.get_one::<String>("output") {
        let mut file = File::create(output)
            .map_err(|error| format!("cannot write {output}: {error}"))?;
        handler.for_each_class_chunk(prefix, |chunk| {
            file.write_all(chunk)
                .map_err(|error| format!("cannot write {output}: {error}"))
        })?;
    } else {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        handler.for_each_class_chunk(prefix, |chunk| {
            out.write_all(chunk)
                .map_err(|error| format!("cannot write stdout: {error}"))
        })?;
    }

    if debug {
        println!(
            "[DEBUG] Total Execution Time: {:.2} us",
            t_start.elapsed().as_secs_f64() * 1_000_000.0
        );
    }
    Ok(())
}

fn _handle_listmethod(args: &ArgMatches) -> Result<(), String> {
    let t_start = Instant::now();
    let apk_path = args.get_one::<String>("apk_path").unwrap();
    let debug = args.get_flag("debug");
    let thread = _get_worker_count(args)?;
    let class = args.get_one::<String>("class_name").map(String::as_str);
    let filter = args.get_one::<String>("filter").map(String::as_str);
    let handler = ApkHandler::new(apk_path, debug, thread);
    if let Some(output) = args.get_one::<String>("output") {
        let mut file = File::create(output)
            .map_err(|error| format!("cannot write {output}: {error}"))?;
        handler.for_each_method_chunk(class, filter, |chunk| {
            file.write_all(chunk)
                .map_err(|error| format!("cannot write {output}: {error}"))
        })?;
    } else {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        handler.for_each_method_chunk(class, filter, |chunk| {
            out.write_all(chunk)
                .map_err(|error| format!("cannot write stdout: {error}"))
        })?;
    }
    if debug {
        println!(
            "[DEBUG] Total Execution Time: {:.2} us",
            t_start.elapsed().as_secs_f64() * 1_000_000.0
        );
    }
    Ok(())
}

fn _handle_liststring(args: &ArgMatches) -> Result<(), String> {
    let t_start = Instant::now();
    let apk_path = args.get_one::<String>("apk_path").unwrap();
    let debug = args.get_flag("debug");
    let thread = _get_worker_count(args)?;
    let filter = args.get_one::<String>("filter").map(String::as_str);
    let handler = ApkHandler::new(apk_path, debug, thread);
    if let Some(output) = args.get_one::<String>("output") {
        let mut file = File::create(output)
            .map_err(|error| format!("cannot write {output}: {error}"))?;
        handler.for_each_string_chunk(filter, |chunk| {
            file.write_all(chunk)
                .map_err(|error| format!("cannot write {output}: {error}"))
        })?;
    } else {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        handler.for_each_string_chunk(filter, |chunk| {
            out.write_all(chunk)
                .map_err(|error| format!("cannot write stdout: {error}"))
        })?;
    }
    if debug {
        println!(
            "[DEBUG] Total Execution Time: {:.2} us",
            t_start.elapsed().as_secs_f64() * 1_000_000.0
        );
    }
    Ok(())
}

fn _export_progress(progress: ExportProgress) {
    match progress {
        ExportProgress::Activity { .. } | ExportProgress::DexInflated { .. } => {}
        ExportProgress::Started {
            total_dex_files,
            worker_count,
        } => eprintln!("APK export: {total_dex_files} DEX files, {worker_count} worker(s)"),
        ExportProgress::DexWorking {
            started_dex_files,
            total_dex_files,
            dex_number,
            busy_workers,
            idle_workers,
            decompile_workers,
            decompile_dex_files,
            inflate_workers,
        } => eprintln!(
            "[apk {started_dex_files}/{total_dex_files} {:5.1}% working] classes{dex_number}.dex | busy={busy_workers} idle={idle_workers} decompile_total={decompile_workers} decompile_dex={decompile_dex_files} inflate={inflate_workers}",
            progress.percentage(),
        ),
        ExportProgress::DexCompleted { .. } => {}
    }
}

fn _handle_export(args: &ArgMatches) -> Result<(), String> {
    let t_start = Instant::now();
    let apk_path = args.get_one::<String>("apk_path").unwrap();
    let output_directory = args.get_one::<String>("output_directory").unwrap();
    let debug = args.get_flag("debug");
    let thread = _get_worker_count(args)?;

    let mut options = ExportOptions::default().with_threads(thread);
    if debug {
        options = options.with_progress(_export_progress);
    }
    let summary = export_to_directory(apk_path, output_directory, options)
        .map_err(|error| format!("cannot export APK: {error}"))?;

    if debug {
        println!(
            "[DEBUG] Exported {} classes from {} DEX file(s) to {} with {} worker(s)",
            summary.classes, summary.dex_files, output_directory, thread,
        );
        println!(
            "[DEBUG] Total Execution Time: {:.2} us",
            t_start.elapsed().as_secs_f64() * 1_000_000.0
        );
    }
    Ok(())
}

fn _handle_getmanifest(args: &ArgMatches) -> Result<(), String> {
    let t_start = Instant::now();
    let apk_path = args.get_one::<String>("apk_path").unwrap();
    let xml = get_manifest_xml(apk_path, true)?;
    if let Some(output) = args.get_one::<String>("output") {
        write_text(output, &xml)?;
    }
    println!("{xml}");

    if args.get_flag("debug") {
        println!(
            "[DEBUG] Total Execution Time: {:.2} us",
            t_start.elapsed().as_secs_f64() * 1_000_000.0
        );
    }
    Ok(())
}

fn _handle_findrefs(args: &ArgMatches) -> Result<(), String> {
    let t_start = Instant::now();
    let apk_path = args.get_one::<String>("apk_path").unwrap();
    let debug = args.get_flag("debug");
    let thread = _get_worker_count(args)?;
    let (find_type, find) = _get_find_query(args)?;
    let apk_handler = ApkHandler::new(apk_path, debug, thread);
    let mut output_fp = args
        .subcommand()
        .and_then(|(_, values)| values.get_one::<String>("output"))
        .map(|path| File::create(path).map_err(|error| format!("cannot create {path}: {error}")))
        .transpose()?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for (_dex_name, lines) in apk_handler.for_each_findrefs(&find_type, &find) {
        if lines.is_empty() {
            continue;
        }
        let text = lines.join("\n") + "\n";
        out.write_all(text.as_bytes())
            .map_err(|error| format!("cannot write stdout: {error}"))?;
        if let Some(file) = output_fp.as_mut() {
            file.write_all(text.as_bytes())
                .map_err(|error| format!("cannot write output: {error}"))?;
        }
    }

    if debug {
        println!(
            "[DEBUG] Total Execution Time: {:.2} us",
            t_start.elapsed().as_secs_f64() * 1_000_000.0
        );
    }
    Ok(())
}

fn _default_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn _get_worker_count(args: &ArgMatches) -> Result<usize, String> {
    let thread = args
        .get_one::<usize>("thread")
        .copied()
        .unwrap_or_else(_default_worker_count);
    if thread == 0 {
        return Err("Worker count must be greater than zero".to_owned());
    }
    Ok(thread)
}

fn common_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("debug")
                .long("debug")
                .action(ArgAction::SetTrue)
                .help("Enable debug profiling output."),
        )
        .arg(
            Arg::new("thread")
                .long("thread")
                .value_parser(value_parser!(usize))
                .help("Worker thread count. Defaults to available CPU count."),
        )
}

fn member_parser(name: &'static str, noun: &'static str, examples: &'static str) -> Command {
    Command::new(name)
        .about(format!("Find references to {noun}s."))
        .after_help(examples)
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Also write reference search output to this file."),
        )
        .arg(Arg::new("name").help(format!("Fuzzy {noun} name.")))
        .arg(
            Arg::new("class_name")
                .long("class")
                .help("Dalvik class or fuzzy class pattern."),
        )
        .arg(
            Arg::new("fuzzy_class")
                .long("fuzzy-class")
                .action(ArgAction::SetTrue)
                .help("Treat --class as fuzzy match."),
        )
}

pub fn _build_main_parser() -> Command {
    let findrefs = common_args(
        Command::new("findrefs")
            .about("Find code references for string/type/method/field across all DEX entries in APK.")
            .after_help(
                "examples:\n  rust_ASC findrefs app.apk string token -o string_refs.txt\n  \
                 rust_ASC findrefs app.apk type com.poc.Main\n  \
                 rust_ASC findrefs app.apk method onCreate --class com.poc.Main\n  \
                 rust_ASC findrefs app.apk method notify --class poc --fuzzy-class -o method_refs.txt\n  \
                 rust_ASC findrefs app.apk field changeQuickRedirect -o field_refs.txt",
            )
            .arg(Arg::new("apk_path").required(true).help("Path to the input APK file."))
            .subcommand_required(true)
            .subcommand(
                Command::new("string")
                    .about("Find references to a fuzzy string.")
                    .arg(
                        Arg::new("output")
                            .short('o')
                            .long("output")
                            .help("Also write reference search output to this file."),
                    )
                    .arg(Arg::new("value").required(true).help("Fuzzy string pattern.")),
            )
            .subcommand(
                Command::new("type")
                    .about("Find references to a fuzzy type descriptor/name.")
                    .arg(
                        Arg::new("output")
                            .short('o')
                            .long("output")
                            .help("Also write reference search output to this file."),
                    )
                    .arg(Arg::new("value").required(true).help("Fuzzy type pattern.")),
            )
            .subcommand(member_parser(
                "method",
                "method",
                "examples:\n  rust_ASC findrefs app.apk method onCreate\n  \
                 rust_ASC findrefs app.apk method notify --class com.poc.Main\n  \
                 rust_ASC findrefs app.apk method notify --class poc --fuzzy-class -o method_refs.txt",
            ))
            .subcommand(member_parser(
                "field",
                "field",
                "examples:\n  rust_ASC findrefs app.apk field changeQuickRedirect\n  \
                 rust_ASC findrefs app.apk field token --class com.poc.Main\n  \
                 rust_ASC findrefs app.apk field token --class poc --fuzzy-class -o field_refs.txt",
            )),
    );

    let command = Command::new("rust_ASC")
        .about("ASC tooling entry.")
        .after_help(
            "examples:\n  rust_ASC getclass app.apk Lcom/poc/Main; -o Main.java\n  \
             rust_ASC getclass --thread 16 app.apk com.poc.Main\n  \
             rust_ASC listclass app.apk -o classes.txt\n  \
             rust_ASC listclass --prefix com.poc app.apk\n  \
             rust_ASC liststring app.apk -f https -o strings.txt\n  \
             rust_ASC export --thread 16 app.apk output\n  \
             rust_ASC getmanifest app.apk -o AndroidManifest.xml\n  \
             rust_ASC findrefs app.apk string token -o string_refs.txt\n  \
             rust_ASC findrefs app.apk type com.poc.Main\n  \
             rust_ASC findrefs app.apk method onCreate --class com.poc.Main\n  \
             rust_ASC findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt\n  \
             rust_ASC findrefs app.apk field apiKey -o field_refs.txt",
        )
        .subcommand_required(true)
        .subcommand(common_args(
            Command::new("getclass")
                .about("Locate the target class in APK, extract one DEX in memory, then decompile.")
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .help("Also write decompiled output to this file."),
                )
                .arg(Arg::new("apk_path").required(true).help("Path to the input APK file."))
                .arg(
                    Arg::new("dalvik_class")
                        .required(true)
                        .help("The Dalvik format class name to extract (e.g., Lcom/poc/Main;)."),
                ),
        ))
        .subcommand(common_args(
            Command::new("listclass")
                .about("List classes across all DEX entries; use --prefix to filter by package/class prefix.")
                .arg(
                    Arg::new("prefix")
                        .long("prefix")
                        .help("Only list classes with this package/class prefix (e.g., com.poc or Lcom/poc)."),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .help("Write class names to this file instead of stdout."),
                )
                .arg(Arg::new("apk_path").required(true).help("Path to the input APK file.")),
        ))
        .subcommand(common_args(
            Command::new("listmethod")
                .about("List method definitions across all DEX entries without decompilation.")
                .arg(Arg::new("apk_path").required(true).help("Path to the input APK file."))
                .arg(
                    Arg::new("class_name")
                        .long("class")
                        .help("Only list methods defined by this class (dotted name or Dalvik descriptor)."),
                )
                .arg(
                    Arg::new("filter")
                        .short('f')
                        .long("filter")
                        .help("Case insensitive substring filter over method names."),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .help("Write method descriptors to this file instead of stdout."),
                ),
        ))
        .subcommand(common_args(
            Command::new("liststring")
                .about("List string pool values across all DEX entries; use --filter to match a substring.")
                .arg(Arg::new("apk_path").required(true).help("Path to the input APK file."))
                .arg(
                    Arg::new("filter")
                        .short('f')
                        .long("filter")
                        .help("Case insensitive substring filter over string values."),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .help("Write string values to this file instead of stdout."),
                ),
        ))
        .subcommand(common_args(
            Command::new("export")
                .about("Export pseudocode for every class in an APK into an output directory.")
                .arg(Arg::new("apk_path").required(true).help("Path to the input APK file."))
                .arg(
                    Arg::new("output_directory")
                        .required(true)
                        .help("Directory where exported .java pseudocode files are written."),
                ),
        ))
        .subcommand(
            Command::new("getmanifest")
                .about("Decode AndroidManifest.xml from APK and print it as XML.")
                .arg(
                    Arg::new("debug")
                        .long("debug")
                        .action(ArgAction::SetTrue)
                        .help("Enable debug profiling output."),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .help("Also write decoded manifest to this file."),
                )
                .arg(Arg::new("apk_path").required(true).help("Path to the input APK file.")),
        )
        .subcommand(findrefs);
    #[cfg(feature = "mcp")]
    let command = command.subcommand(Command::new("mcp").about("Serve MCP tools over stdio."));
    command
}

pub fn run_from<I, T>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = _build_main_parser()
        .try_get_matches_from(args)
        .map_err(|error| error.to_string())?;
    match matches.subcommand() {
        #[cfg(feature = "mcp")]
        Some(("mcp", _)) => crate::mcp::run(),
        Some(("getclass", args)) => _handle_getclass(args),
        Some(("listclass", args)) => _handle_listclass(args),
        Some(("listmethod", args)) => _handle_listmethod(args),
        Some(("liststring", args)) => _handle_liststring(args),
        Some(("export", args)) => _handle_export(args),
        Some(("getmanifest", args)) => _handle_getmanifest(args),
        Some(("findrefs", args)) => _handle_findrefs(args),
        _ => Err("Unknown command".to_owned()),
    }
}

pub fn main() {
    if std::env::args_os().len() == 1 {
        let mut parser = _build_main_parser();
        let _ = parser.print_help();
        println!();
        return;
    }
    if let Err(error) = run_from(std::env::args_os()) {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}
