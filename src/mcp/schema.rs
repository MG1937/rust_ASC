use std::ffi::OsString;

use rmcp::model::{Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct GetClass {
    /// Path to the APK to analyze.
    apk_path: String,
    /// Single dotted class name or Dalvik descriptor.
    class_name: Option<String>,
    /// Optional list of dotted class names or Dalvik descriptors for batch decompilation.
    classes: Option<Vec<String>>,
    /// Optional file containing class names, one per line.
    classes_file: Option<String>,
    /// Emit structured JSON with source and member reference metadata.
    #[serde(default)]
    json: bool,
    /// Positive worker count. Defaults to available CPU count.
    thread: Option<usize>,
    /// Optional source output file. Existing files are overwritten. Content is also returned.
    output: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListClass {
    /// Path to the APK to analyze.
    apk_path: String,
    /// Optional case sensitive class or package prefix.
    prefix: Option<String>,
    /// Emit class descriptors as a JSON array.
    #[serde(default)]
    json: bool,
    /// Positive worker count. Defaults to available CPU count.
    thread: Option<usize>,
    /// Optional class list output file. When set, stdout is empty. Existing files are overwritten.
    output: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListMethod {
    /// Path to the APK to analyze.
    apk_path: String,
    /// Only list methods defined by this class. Accepts a dotted name or Dalvik descriptor.
    class_name: Option<String>,
    /// Optional case insensitive substring filter over method names.
    filter: Option<String>,
    /// Emit method descriptors as a JSON array.
    #[serde(default)]
    json: bool,
    /// Positive worker count. Defaults to available CPU count.
    thread: Option<usize>,
    /// Optional method list output file. When set, stdout is empty. Existing files are overwritten.
    output: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListString {
    /// Path to the APK to analyze.
    apk_path: String,
    /// Optional case insensitive substring filter over string values.
    filter: Option<String>,
    /// Deduplicate string values across DEX files in first occurrence order.
    #[serde(default)]
    unique: bool,
    /// Emit string values as a JSON array.
    #[serde(default)]
    json: bool,
    /// Positive worker count. Defaults to available CPU count.
    thread: Option<usize>,
    /// Optional string list output file. When set, stdout is empty. Existing files are overwritten.
    output: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct GetManifest {
    /// Path to the APK to analyze.
    apk_path: String,
    /// Optional XML output file. Existing files are overwritten. Content is also returned.
    output: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FindRefs {
    /// Path to the APK to analyze.
    apk_path: String,
    /// Reference target and match mode.
    query: RefQuery,
    /// Emit structured JSON reference records.
    #[serde(default)]
    json: bool,
    /// Positive worker count. Defaults to available CPU count.
    thread: Option<usize>,
    /// Optional reference output file. Existing files are overwritten. Content is also returned.
    output: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RefQuery {
    /// Find string constant references.
    String {
        /// Case sensitive string constant substring.
        value: String,
        /// Optional maximum character length for displayed string constants.
        max_match: Option<usize>,
        /// Omit matched string constant values from output.
        #[serde(default)]
        no_match: bool,
    },
    /// Find type references.
    Type {
        /// Case sensitive Dalvik type descriptor substring.
        value: String,
    },
    /// Find direct subclasses.
    Extends {
        /// Dotted class name or Dalvik descriptor.
        value: String,
    },
    /// Find direct interface implementors.
    Impl {
        /// Dotted class name or Dalvik descriptor.
        value: String,
    },
    /// Find method call references.
    Method {
        /// Case sensitive method name substring. Supply name, class_name, or both.
        name: Option<String>,
        /// Dotted name or Dalvik descriptor of the declaring class.
        class_name: Option<String>,
        /// Match class_name as a case sensitive descriptor substring.
        #[serde(default)]
        fuzzy_class: bool,
    },
    /// Find field access references.
    Field {
        /// Case sensitive field name substring. Supply name, class_name, or both.
        name: Option<String>,
        /// Dotted name or Dalvik descriptor of the declaring class.
        class_name: Option<String>,
        /// Match class_name as a case sensitive descriptor substring.
        #[serde(default)]
        fuzzy_class: bool,
    },
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Export {
    /// Path to the APK to analyze.
    apk_path: String,
    /// Directory where exported Java pseudocode files are written. Content is also returned.
    output: String,
    /// Optional case sensitive class or package prefix.
    prefix: Option<String>,
    /// Optional file containing class names, one per line.
    classes_file: Option<String>,
    /// Positive worker count. Defaults to available CPU count.
    thread: Option<usize>,
}

fn tool<I: JsonSchema + 'static>(name: &'static str, description: &'static str) -> Tool {
    Tool::new(name, description, serde_json::Map::new())
        .with_input_schema::<I>()
        .with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(true)
                .idempotent(true)
                .open_world(false),
        )
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool::<GetClass>("getclass", "Decompile one or more APK classes to Java like source."),
        tool::<ListClass>(
            "listclass",
            "List class descriptors from every DEX in an APK.",
        ),
        tool::<ListMethod>(
            "listmethod",
            "List defined method descriptors from every DEX in an APK.",
        ),
        tool::<ListString>(
            "liststring",
            "List string pool values from every DEX in an APK.",
        ),
        tool::<GetManifest>(
            "getmanifest",
            "Decode AndroidManifest.xml to formatted XML.",
        ),
        tool::<FindRefs>(
            "findrefs",
            "Find methods that reference strings, types, methods, or fields.",
        ),
        tool::<Export>(
            "export",
            "Export pseudocode for selected APK classes into an output directory.",
        ),
    ]
}

pub(super) struct Query {
    args: Vec<OsString>,
}

impl Query {
    pub(super) fn parse(name: &str, args: Value) -> Result<Self, String> {
        let args = match name {
            "getclass" => getclass(serde_json::from_value(args).map_err(invalid_args)?)?,
            "listclass" => listclass(serde_json::from_value(args).map_err(invalid_args)?),
            "listmethod" => listmethod(serde_json::from_value(args).map_err(invalid_args)?),
            "liststring" => liststring(serde_json::from_value(args).map_err(invalid_args)?),
            "getmanifest" => getmanifest(serde_json::from_value(args).map_err(invalid_args)?),
            "findrefs" => findrefs(serde_json::from_value(args).map_err(invalid_args)?),
            "export" => export(serde_json::from_value(args).map_err(invalid_args)?),
            _ => return Err("unknown tool".to_owned()),
        };
        Ok(Self { args })
    }
}

fn invalid_args(error: serde_json::Error) -> String {
    format!("invalid arguments: {error}")
}

fn push_thread(args: &mut Vec<OsString>, thread: Option<usize>) {
    if let Some(thread) = thread {
        args.push("--thread".into());
        args.push(thread.to_string().into());
    }
}

fn getclass(input: GetClass) -> Result<Vec<OsString>, String> {
    if input.class_name.is_none()
        && input.classes.as_ref().is_none_or(Vec::is_empty)
        && input.classes_file.is_none()
    {
        return Err("invalid arguments: missing field `class_name`".to_owned());
    }
    let mut args = vec!["getclass".into()];
    push_thread(&mut args, input.thread);
    if input.json {
        args.push("--json".into());
    }
    if let Some(classes_file) = input.classes_file {
        args.push("--classes-file".into());
        args.push(classes_file.into());
    }
    push_output(&mut args, input.output);
    args.push(input.apk_path.into());
    if let Some(class_name) = input.class_name {
        args.push(class_name.into());
    }
    if let Some(classes) = input.classes {
        for cls in classes {
            args.push(cls.into());
        }
    }
    Ok(args)
}

fn listclass(input: ListClass) -> Vec<OsString> {
    let mut args = vec!["listclass".into()];
    push_thread(&mut args, input.thread);
    if input.json {
        args.push("--json".into());
    }
    if let Some(prefix) = input.prefix {
        args.push("--prefix".into());
        args.push(prefix.into());
    }
    args.push(input.apk_path.into());
    push_output(&mut args, input.output);
    args
}

fn listmethod(input: ListMethod) -> Vec<OsString> {
    let mut args = vec!["listmethod".into()];
    push_thread(&mut args, input.thread);
    if input.json {
        args.push("--json".into());
    }
    if let Some(class) = input.class_name {
        args.push(format!("--class={class}").into());
    }
    if let Some(filter) = input.filter {
        args.push(format!("--filter={filter}").into());
    }
    push_output(&mut args, input.output);
    args.push("--".into());
    args.push(input.apk_path.into());
    args
}

fn liststring(input: ListString) -> Vec<OsString> {
    let mut args = vec!["liststring".into()];
    push_thread(&mut args, input.thread);
    if input.unique {
        args.push("--unique".into());
    }
    if input.json {
        args.push("--json".into());
    }
    if let Some(filter) = input.filter {
        args.push(format!("--filter={filter}").into());
    }
    push_output(&mut args, input.output);
    args.push("--".into());
    args.push(input.apk_path.into());
    args
}

fn getmanifest(input: GetManifest) -> Vec<OsString> {
    let mut args = vec!["getmanifest".into(), input.apk_path.into()];
    push_output(&mut args, input.output);
    args
}

fn findrefs(input: FindRefs) -> Vec<OsString> {
    let mut args = vec!["findrefs".into()];
    push_thread(&mut args, input.thread);
    if input.json {
        args.push("--json".into());
    }
    args.push(input.apk_path.into());
    match input.query {
        RefQuery::String {
            value,
            max_match,
            no_match,
        } => {
            args.push("string".into());
            if let Some(max_match) = max_match {
                args.push("--max-match".into());
                args.push(max_match.to_string().into());
            }
            if no_match {
                args.push("--no-match".into());
            }
            args.push(value.into());
        }
        RefQuery::Type { value } => {
            args.push("type".into());
            args.push(value.into());
        }
        RefQuery::Extends { value } => {
            args.push("extends".into());
            args.push(value.into());
        }
        RefQuery::Impl { value } => {
            args.push("impl".into());
            args.push(value.into());
        }
        RefQuery::Method {
            name,
            class_name,
            fuzzy_class,
        } => push_member(&mut args, "method", name, class_name, fuzzy_class),
        RefQuery::Field {
            name,
            class_name,
            fuzzy_class,
        } => push_member(&mut args, "field", name, class_name, fuzzy_class),
    }
    push_output(&mut args, input.output);
    args
}

fn export(input: Export) -> Vec<OsString> {
    let mut args = vec!["export".into()];
    push_thread(&mut args, input.thread);
    if let Some(prefix) = input.prefix {
        args.push("--prefix".into());
        args.push(prefix.into());
    }
    if let Some(classes_file) = input.classes_file {
        args.push("--classes-file".into());
        args.push(classes_file.into());
    }
    args.push(input.apk_path.into());
    args.push(input.output.into());
    args
}

fn push_output(args: &mut Vec<OsString>, output: Option<String>) {
    if let Some(output) = output {
        args.push("-o".into());
        args.push(output.into());
    }
}

fn push_member(
    args: &mut Vec<OsString>,
    kind: &str,
    name: Option<String>,
    class_name: Option<String>,
    fuzzy_class: bool,
) {
    args.push(kind.into());
    if let Some(name) = name {
        args.push(name.into());
    }
    if let Some(class_name) = class_name {
        args.push("--class".into());
        args.push(class_name.into());
    }
    if fuzzy_class {
        args.push("--fuzzy-class".into());
    }
}

pub(super) fn execute(query: Query) -> Result<String, String> {
    let mut cli_args = Vec::with_capacity(query.args.len() + 1);
    cli_args.push(OsString::from("rust_ASC"));
    cli_args.extend(query.args);
    let mut out = Vec::new();
    crate::cli::run_from_into(cli_args, &mut out).map_err(|err| format!("Error: {err}"))?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}
