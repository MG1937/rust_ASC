use std::ffi::OsString;
use std::process::Command;

use rmcp::model::{Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct GetClass {
    /// Path to the APK to analyze.
    apk_path: String,
    /// Dotted class name or Dalvik descriptor.
    class_name: String,
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
    /// Positive worker count. Defaults to available CPU count.
    thread: Option<usize>,
    /// Optional class list output file. When set, stdout is empty. Existing files are overwritten.
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
    },
    /// Find type references.
    Type {
        /// Case sensitive Dalvik type descriptor substring.
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
        tool::<GetClass>("getclass", "Decompile one APK class to Java like source."),
        tool::<ListClass>(
            "listclass",
            "List class descriptors from every DEX in an APK.",
        ),
        tool::<GetManifest>(
            "getmanifest",
            "Decode AndroidManifest.xml to formatted XML.",
        ),
        tool::<FindRefs>(
            "findrefs",
            "Find methods that reference strings, types, methods, or fields.",
        ),
    ]
}

pub(super) struct Query {
    args: Vec<OsString>,
}

impl Query {
    pub(super) fn parse(name: &str, args: Value) -> Result<Self, String> {
        let args = match name {
            "getclass" => getclass(serde_json::from_value(args).map_err(invalid_args)?),
            "listclass" => listclass(serde_json::from_value(args).map_err(invalid_args)?),
            "getmanifest" => getmanifest(serde_json::from_value(args).map_err(invalid_args)?),
            "findrefs" => findrefs(serde_json::from_value(args).map_err(invalid_args)?),
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

fn getclass(input: GetClass) -> Vec<OsString> {
    let mut args = vec!["getclass".into()];
    push_thread(&mut args, input.thread);
    args.push(input.apk_path.into());
    args.push(input.class_name.into());
    push_output(&mut args, input.output);
    args
}

fn listclass(input: ListClass) -> Vec<OsString> {
    let mut args = vec!["listclass".into()];
    push_thread(&mut args, input.thread);
    if let Some(prefix) = input.prefix {
        args.push("--prefix".into());
        args.push(prefix.into());
    }
    args.push(input.apk_path.into());
    push_output(&mut args, input.output);
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
    args.push(input.apk_path.into());
    match input.query {
        RefQuery::String { value } => {
            args.push("string".into());
            args.push(value.into());
        }
        RefQuery::Type { value } => {
            args.push("type".into());
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
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve rust_ASC executable: {error}"))?;
    let output = Command::new(executable)
        .args(query.args)
        .output()
        .map_err(|error| format!("cannot start rust_ASC CLI: {error}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = stderr.trim();
    if message.is_empty() {
        Err(format!("rust_ASC CLI exited with {}", output.status))
    } else {
        Err(message.to_owned())
    }
}
