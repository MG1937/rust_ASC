use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::time::Instant;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use radguard::cli::{ExportOptions, ExportProgress, export_to_directory};
use serde::Serialize;

use crate::asc_client::apk_handler::ApkHandler;
use crate::asc_client::asc_handler::{AscHandler, FindRefsDisplayOptions};
use crate::asc_client::manifest_handler::get_manifest_xml;
use crate::asc_core::findrefs::findrefs_manager::FindRefInput;
use crate::asc_core::findrefs::locator::field_locator::FieldFind;
use crate::asc_core::findrefs::locator::method_locator::MethodFind;
use crate::asc_core::utils::decompiler::{MemberKind, MemberReference};

#[derive(Serialize)]
struct MemberRefDto<'a> {
    start: usize,
    end: usize,
    kind: &'static str,
    class: &'a str,
    name: &'a str,
    descriptor: &'a str,
    declaration: bool,
}

impl<'a> From<&'a MemberReference> for MemberRefDto<'a> {
    fn from(r: &'a MemberReference) -> Self {
        Self {
            start: r.start,
            end: r.end,
            kind: match r.kind {
                MemberKind::Field => "field",
                MemberKind::Method => "method",
            },
            class: &r.class,
            name: &r.name,
            descriptor: &r.descriptor,
            declaration: r.declaration,
        }
    }
}

#[derive(Serialize)]
struct GetClassJsonItem<'a> {
    class: &'a str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dex: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    member_references: Vec<MemberRefDto<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn _load_classes_from_file(path: &str) -> Result<Vec<String>, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("cannot read classes file {path}: {error}"))?;
    let mut classes = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim().trim_start_matches('\u{feff}');
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        classes.push(_format_class_name(trimmed)?);
    }
    Ok(classes)
}

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
            extends: None,
            impl_: None,
        }),
        "field" => Ok(FindRefInput {
            string: None,
            type_: None,
            method: None,
            field: Some(FieldFind::new(class, name.map(str::to_owned))),
            extends: None,
            impl_: None,
        }),
        _ => Err(format!("Unknown member type: {key}")),
    }
}

fn _get_find_query(args: &ArgMatches) -> Result<(String, FindRefInput, FindRefsDisplayOptions), String> {
    let (find_type, find_args) = args
        .subcommand()
        .ok_or_else(|| "Unknown find type".to_owned())?;
    let mut display = FindRefsDisplayOptions::default();
    let find = match find_type {
        "string" => {
            display.max_match = find_args.get_one::<usize>("max_match").copied();
            display.no_match = find_args.get_flag("no_match");
            FindRefInput {
                string: find_args.get_one::<String>("value").cloned(),
                type_: None,
                method: None,
                field: None,
                extends: None,
                impl_: None,
            }
        }
        "type" => {
            let value = find_args.get_one::<String>("value").map(|v| {
                if v.contains('.') && !v.contains('/') {
                    v.replace('.', "/")
                } else {
                    v.clone()
                }
            });
            FindRefInput {
                string: None,
                type_: value,
                method: None,
                field: None,
                extends: None,
                impl_: None,
            }
        }
        "extends" | "impl" => {
            let target = _format_class_name(find_args.get_one::<String>("value").unwrap())?;
            FindRefInput {
                string: None,
                type_: None,
                method: None,
                field: None,
                extends: (find_type == "extends").then(|| target.clone()),
                impl_: (find_type == "impl").then_some(target),
            }
        }
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
    Ok((find_type.to_owned(), find, display))
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
    let debug = args.get_flag("debug");
    let json_output = args.get_flag("json");
    let thread = _get_worker_count(args)?;

    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    if let Some(values) = args.get_many::<String>("dalvik_class") {
        for raw in values {
            let formatted = _format_class_name(raw)?;
            if seen.insert(formatted.clone()) {
                targets.push(formatted);
            }
        }
    }
    if let Some(classes_file) = args.get_one::<String>("classes_file") {
        for formatted in _load_classes_from_file(classes_file)? {
            if seen.insert(formatted.clone()) {
                targets.push(formatted);
            }
        }
    }
    if targets.is_empty() {
        return Err("At least one class name or --classes-file is required".to_owned());
    }

    let apk_handler = ApkHandler::new(apk_path, debug, thread);
    if targets.len() == 1 && !json_output {
        let dalvik_class = &targets[0];
        let (dex_name, dex_buf) = apk_handler
            .try_get_class_dex(dalvik_class)?
            .ok_or_else(|| format!("Class {dalvik_class} not found in APK."))?;
        let t_hit_end = Instant::now();
        let source_code = AscHandler::new(debug).getclass(&dex_buf, dalvik_class);
        let t_end = Instant::now();

        if debug {
            eprintln!("[DEBUG] Hit DEX: {dex_name}");
            eprintln!(
                "[DEBUG] APK Scan Time: {:.2} us",
                (t_hit_end - t_start).as_secs_f64() * 1_000_000.0
            );
            eprintln!(
                "[DEBUG] Total Execution Time: {:.2} us",
                (t_end - t_start).as_secs_f64() * 1_000_000.0
            );
            eprintln!("{}", "-".repeat(50));
        }

        if let Some(output) = args.get_one::<String>("output") {
            write_text(output, &source_code)?;
        }
        println!("{source_code}");
        return Ok(());
    }

    let results = apk_handler.try_get_classes_batch(&targets, json_output)?;
    let t_end = Instant::now();

    if debug {
        eprintln!(
            "[DEBUG] Batch decompiled {} class(es) in {:.2} us",
            targets.len(),
            (t_end - t_start).as_secs_f64() * 1_000_000.0
        );
    }

    if json_output {
        let mut missing = Vec::new();
        let items: Vec<GetClassJsonItem<'_>> = results
            .iter()
            .map(|(cls, entry)| match entry {
                Some((dex_name, source, refs)) => GetClassJsonItem {
                    class: cls.as_str(),
                    status: "ok",
                    dex: Some(dex_name.as_str()),
                    source: Some(source.as_str()),
                    member_references: refs.iter().map(MemberRefDto::from).collect(),
                    error: None,
                },
                None => {
                    missing.push(cls.clone());
                    GetClassJsonItem {
                        class: cls.as_str(),
                        status: "not_found",
                        dex: None,
                        source: None,
                        member_references: Vec::new(),
                        error: Some(format!("Class {cls} not found in APK.")),
                    }
                }
            })
            .collect();
        let serialized = if items.len() == 1 {
            if let Some(err) = &items[0].error {
                return Err(err.clone());
            }
            serde_json::to_string_pretty(&items[0])
                .map_err(|error| format!("cannot serialize JSON: {error}"))?
        } else {
            serde_json::to_string_pretty(&items)
                .map_err(|error| format!("cannot serialize JSON: {error}"))?
        };
        if let Some(output) = args.get_one::<String>("output") {
            write_text(output, &serialized)?;
        }
        println!("{serialized}");
        if !missing.is_empty() {
            return Err(format!(
                "Class {} not found in APK.",
                missing.join(", ")
            ));
        }
        return Ok(());
    }

    let mut combined = String::new();
    let mut missing = Vec::new();
    for (idx, (cls, entry)) in results.iter().enumerate() {
        match entry {
            Some((dex_name, source, _)) => {
                if idx > 0 && !combined.ends_with('\n') {
                    combined.push('\n');
                }
                combined.push_str(&format!("// === Class: {cls} ({dex_name}) ===\n"));
                combined.push_str(source);
                if !combined.ends_with('\n') {
                    combined.push('\n');
                }
            }
            None => missing.push(cls.clone()),
        }
    }
    if let Some(output) = args.get_one::<String>("output") {
        write_text(output, &combined)?;
    }
    if !combined.is_empty() {
        print!("{combined}");
    }
    if !missing.is_empty() {
        return Err(format!(
            "Class {} not found in APK.",
            missing.join(", ")
        ));
    }
    Ok(())
}

fn _write_json_lines_from_chunks<W: Write>(
    mut writer: W,
    chunks_fn: impl FnOnce(&mut dyn FnMut(&[u8]) -> Result<(), String>) -> Result<usize, String>,
) -> Result<(), String> {
    writer
        .write_all(b"[")
        .map_err(|e| format!("cannot write JSON output: {e}"))?;
    let mut first = true;
    let mut pending = Vec::new();
    chunks_fn(&mut |chunk| {
        pending.extend_from_slice(chunk);
        while let Some(pos) = memchr::memchr(b'\n', &pending) {
            let line = String::from_utf8_lossy(&pending[..pos]);
            let prefix = if first {
                first = false;
                "\n  "
            } else {
                ",\n  "
            };
            writer
                .write_all(prefix.as_bytes())
                .map_err(|e| format!("cannot write JSON output: {e}"))?;
            serde_json::to_writer(&mut writer, line.as_ref())
                .map_err(|e| format!("cannot write JSON output: {e}"))?;
            pending.drain(..=pos);
        }
        Ok(())
    })?;
    if !pending.is_empty() {
        let line = String::from_utf8_lossy(&pending);
        let prefix = if first {
            first = false;
            "\n  "
        } else {
            ",\n  "
        };
        writer
            .write_all(prefix.as_bytes())
            .map_err(|e| format!("cannot write JSON output: {e}"))?;
        serde_json::to_writer(&mut writer, line.as_ref())
            .map_err(|e| format!("cannot write JSON output: {e}"))?;
    }
    let closing = if first { "]\n" } else { "\n]\n" };
    writer
        .write_all(closing.as_bytes())
        .map_err(|e| format!("cannot write JSON output: {e}"))?;
    writer
        .flush()
        .map_err(|e| format!("cannot flush JSON output: {e}"))
}

fn _handle_listclass(args: &ArgMatches) -> Result<(), String> {
    let t_start = Instant::now();
    let apk_path = args.get_one::<String>("apk_path").unwrap();
    let debug = args.get_flag("debug");
    let json_output = args.get_flag("json");
    let thread = _get_worker_count(args)?;
    let prefix = args.get_one::<String>("prefix").map(String::as_str);
    let handler = ApkHandler::new(apk_path, debug, thread);
    if json_output {
        if let Some(output) = args.get_one::<String>("output") {
            let file = File::create(output)
                .map_err(|error| format!("cannot write {output}: {error}"))?;
            _write_json_lines_from_chunks(BufWriter::new(file), |cb| {
                handler.for_each_class_chunk(prefix, cb)
            })?;
        } else {
            let stdout = io::stdout();
            _write_json_lines_from_chunks(BufWriter::new(stdout.lock()), |cb| {
                handler.for_each_class_chunk(prefix, cb)
            })?;
        }
    } else if let Some(output) = args.get_one::<String>("output") {
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
        eprintln!(
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
    let json_output = args.get_flag("json");
    let thread = _get_worker_count(args)?;
    let class = args.get_one::<String>("class_name").map(String::as_str);
    let filter = args.get_one::<String>("filter").map(String::as_str);
    let handler = ApkHandler::new(apk_path, debug, thread);
    if json_output {
        if let Some(output) = args.get_one::<String>("output") {
            let file = File::create(output)
                .map_err(|error| format!("cannot write {output}: {error}"))?;
            _write_json_lines_from_chunks(BufWriter::new(file), |cb| {
                handler.for_each_method_chunk(class, filter, cb)
            })?;
        } else {
            let stdout = io::stdout();
            _write_json_lines_from_chunks(BufWriter::new(stdout.lock()), |cb| {
                handler.for_each_method_chunk(class, filter, cb)
            })?;
        }
    } else if let Some(output) = args.get_one::<String>("output") {
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
        eprintln!(
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
    let json_output = args.get_flag("json");
    let unique = args.get_flag("unique");
    let thread = _get_worker_count(args)?;
    let filter = args.get_one::<String>("filter").map(String::as_str);
    let handler = ApkHandler::new(apk_path, debug, thread);

    if json_output || unique {
        let mut writer: Box<dyn Write> = if let Some(output) = args.get_one::<String>("output") {
            Box::new(BufWriter::new(
                File::create(output).map_err(|error| format!("cannot write {output}: {error}"))?,
            ))
        } else {
            Box::new(BufWriter::new(io::stdout().lock()))
        };
        let mut seen = unique.then(HashSet::new);
        if json_output {
            writer
                .write_all(b"[")
                .map_err(|e| format!("cannot write output: {e}"))?;
        }
        let mut first = true;
        handler.for_each_string_record(filter, |value| {
            if let Some(ref mut set) = seen
                && !set.insert(value.clone())
            {
                return Ok(());
            }
            if json_output {
                let prefix = if first {
                    first = false;
                    "\n  "
                } else {
                    ",\n  "
                };
                writer
                    .write_all(prefix.as_bytes())
                    .map_err(|e| format!("cannot write output: {e}"))?;
                serde_json::to_writer(&mut writer, &value)
                    .map_err(|e| format!("cannot write output: {e}"))?;
            } else {
                writer
                    .write_all(value.as_bytes())
                    .and_then(|()| writer.write_all(b"\n"))
                    .map_err(|e| format!("cannot write output: {e}"))?;
            }
            Ok(())
        })?;
        if json_output {
            let closing = if first { "]\n" } else { "\n]\n" };
            writer
                .write_all(closing.as_bytes())
                .map_err(|e| format!("cannot write output: {e}"))?;
        }
        writer
            .flush()
            .map_err(|e| format!("cannot flush output: {e}"))?;
    } else if let Some(output) = args.get_one::<String>("output") {
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
        eprintln!(
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

    let prefix = args
        .get_one::<String>("prefix")
        .map(String::as_str)
        .map(str::trim)
        .map(|p| {
            if p.is_empty() {
                return Err("Class prefix cannot be empty".to_owned());
            }
            Ok(if p.starts_with('L') {
                p.to_owned()
            } else {
                format!("L{}", p.replace('.', "/"))
            })
        })
        .transpose()?;
    let classes_whitelist = args
        .get_one::<String>("classes_file")
        .map(|path| _load_classes_from_file(path))
        .transpose()?
        .map(|list| list.into_iter().collect::<HashSet<String>>());

    let mut options = ExportOptions::default().with_threads(thread);
    if debug {
        options = options.with_progress(_export_progress);
    }
    if prefix.is_some() || classes_whitelist.is_some() {
        options = options.with_class_filter(move |descriptor| {
            if let Some(ref p) = prefix
                && !descriptor.starts_with(p.as_str())
            {
                return false;
            }
            if let Some(ref set) = classes_whitelist
                && !set.contains(descriptor)
            {
                return false;
            }
            true
        });
    }
    let summary = export_to_directory(apk_path, output_directory, options)
        .map_err(|error| format!("cannot export APK: {error}"))?;

    if debug {
        eprintln!(
            "[DEBUG] Exported {} classes from {} DEX file(s) to {} with {} worker(s)",
            summary.classes, summary.dex_files, output_directory, thread,
        );
        eprintln!(
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
        eprintln!(
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
    let json_output = args.get_flag("json");
    let thread = _get_worker_count(args)?;
    let (find_type, find, display) = _get_find_query(args)?;
    let apk_handler = ApkHandler::new(apk_path, debug, thread);
    let output_path = args
        .subcommand()
        .and_then(|(_, values)| values.get_one::<String>("output").cloned());

    if json_output {
        let dex_records = apk_handler.try_for_each_findrefs_records(&find_type, &find, display)?;
        let flat: Vec<_> = dex_records
            .into_iter()
            .flat_map(|(_, records)| records)
            .collect();
        let serialized = serde_json::to_string_pretty(&flat)
            .map_err(|error| format!("cannot serialize JSON: {error}"))?;
        if let Some(ref path) = output_path {
            write_text(path, &serialized)?;
        }
        println!("{serialized}");
    } else {
        let dex_lines = apk_handler.try_for_each_findrefs(&find_type, &find, display)?;
        let mut output_fp = output_path
            .as_deref()
            .map(|path| File::create(path).map_err(|error| format!("cannot create {path}: {error}")))
            .transpose()?;
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for (_dex_name, lines) in dex_lines {
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
    }

    if debug {
        eprintln!(
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
                 rust_ASC findrefs app.apk extends android.app.Activity -o subclasses.txt\n  \
                 rust_ASC findrefs app.apk impl android.os.IInterface -o impls.txt\n  \
                 rust_ASC findrefs app.apk method onCreate --class com.poc.Main\n  \
                 rust_ASC findrefs app.apk method notify --class poc --fuzzy-class -o method_refs.txt\n  \
                 rust_ASC findrefs app.apk field changeQuickRedirect -o field_refs.txt",
            )
            .arg(Arg::new("apk_path").required(true).help("Path to the input APK file."))
            .arg(
                Arg::new("json")
                    .long("json")
                    .global(true)
                    .action(ArgAction::SetTrue)
                    .help("Emit structured JSON reference records."),
            )
            .subcommand_required(true)
            .subcommand(
                Command::new("string")
                    .about("Find references to a fuzzy string.")
                    .arg(
                        Arg::new("max_match")
                            .long("max-match")
                            .value_parser(value_parser!(usize))
                            .help("Truncate displayed string constants to N characters."),
                    )
                    .arg(
                        Arg::new("no_match")
                            .long("no-match")
                            .action(ArgAction::SetTrue)
                            .help("Omit matched constant values from output."),
                    )
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
            .subcommand(
                Command::new("extends")
                    .about("Find classes that extend the target class.")
                    .arg(
                        Arg::new("output")
                            .short('o')
                            .long("output")
                            .help("Also write subclass output to this file."),
                    )
                    .arg(
                        Arg::new("value")
                            .required(true)
                            .help("Target class in dotted or Dalvik form."),
                    ),
            )
            .subcommand(
                Command::new("impl")
                    .about("Find classes that implement the target interface.")
                    .arg(
                        Arg::new("output")
                            .short('o')
                            .long("output")
                            .help("Also write implementor output to this file."),
                    )
                    .arg(
                        Arg::new("value")
                            .required(true)
                            .help("Target interface in dotted or Dalvik form."),
                    ),
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
        .version(env!("CARGO_PKG_VERSION"))
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
             rust_ASC findrefs app.apk extends android.app.Activity -o subclasses.txt\n  \
             rust_ASC findrefs app.apk impl android.os.IInterface -o impls.txt\n  \
             rust_ASC findrefs app.apk method onCreate --class com.poc.Main\n  \
             rust_ASC findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt\n  \
             rust_ASC findrefs app.apk field apiKey -o field_refs.txt",
        )
        .subcommand_required(true)
        .subcommand(common_args(
            Command::new("getclass")
                .about("Locate one or more classes in APK and decompile them in a single process.")
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .help("Also write decompiled output to this file."),
                )
                .arg(
                    Arg::new("classes_file")
                        .long("classes-file")
                        .help("Read class names from this file, one per line."),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Emit JSON with source and member reference metadata."),
                )
                .arg(Arg::new("apk_path").required(true).help("Path to the input APK file."))
                .arg(
                    Arg::new("dalvik_class")
                        .num_args(0..)
                        .help("The Dalvik class name(s) to decompile (e.g., Lcom/poc/Main; or com.poc.Main)."),
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
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Emit class descriptors as a JSON array."),
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
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Emit method descriptors as a JSON array."),
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
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Emit string values as a JSON array."),
                )
                .arg(
                    Arg::new("unique")
                        .short('u')
                        .long("unique")
                        .action(ArgAction::SetTrue)
                        .help("Deduplicate string values across DEX files, keeping first occurrence order."),
                ),
        ))
        .subcommand(common_args(
            Command::new("export")
                .about("Export pseudocode for selected classes in an APK into an output directory.")
                .arg(Arg::new("apk_path").required(true).help("Path to the input APK file."))
                .arg(
                    Arg::new("output_directory")
                        .required(true)
                        .help("Directory where exported .java pseudocode files are written."),
                )
                .arg(
                    Arg::new("prefix")
                        .long("prefix")
                        .help("Only export classes with this package/class prefix (e.g., com.poc or Lcom/poc)."),
                )
                .arg(
                    Arg::new("classes_file")
                        .long("classes-file")
                        .help("Only export classes listed in this file, one per line."),
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
    let matches = match _build_main_parser().try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error) => {
            if error.kind() == clap::error::ErrorKind::DisplayVersion {
                print!("{error}");
                return Ok(());
            }
            return Err(error.to_string());
        }
    };
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
