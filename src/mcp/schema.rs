use rmcp::model::{CallToolResult, Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::asc_client::asc_handler::Reference;
use crate::asc_client::query::{ApkQuery, ClassSource, QueryError};
use crate::asc_client::query_input::_build_member_find;
use crate::asc_core::findrefs::findrefs_manager::FindRefInput;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GetClass {
    /// Absolute path to an APK on the MCP server's local filesystem.
    pub apk_path: String,
    /// Dalvik descriptor (Lcom/example/Main;) or dotted class name.
    pub class_name: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ListClass {
    /// Absolute path to an APK on the MCP server's local filesystem.
    pub apk_path: String,
    /// Optional class/package prefix, such as com.example or Lcom/example.
    pub prefix: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GetManifest {
    /// Absolute path to an APK on the MCP server's local filesystem.
    pub apk_path: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct FindRefs {
    /// Absolute path to an APK on the MCP server's local filesystem.
    pub apk_path: String,
    pub query: RefQuery,
}

#[derive(Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RefQuery {
    String {
        value: String,
    },
    Type {
        value: String,
    },
    Method {
        /// Fuzzy method name. Supply name, class_name, or both.
        name: Option<String>,
        class_name: Option<String>,
        /// If false, class_name is an exact descriptor/dotted class name.
        #[serde(default)]
        fuzzy_class: bool,
    },
    Field {
        /// Fuzzy field name. Supply name, class_name, or both.
        name: Option<String>,
        class_name: Option<String>,
        #[serde(default)]
        fuzzy_class: bool,
    },
}

impl RefQuery {
    fn into_find(self) -> Result<(&'static str, FindRefInput), QueryError> {
        let kind = match &self {
            Self::String { .. } => "string",
            Self::Type { .. } => "type",
            Self::Method { .. } => "method",
            Self::Field { .. } => "field",
        };
        let find = match self {
            Self::String { value } => FindRefInput::new(Some(value), None, None, None),
            Self::Type { value } => FindRefInput::new(None, Some(value), None, None),
            Self::Method {
                name,
                class_name,
                fuzzy_class,
            }
            | Self::Field {
                name,
                class_name,
                fuzzy_class,
            } => _build_member_find(kind, class_name.as_deref(), fuzzy_class, name.as_deref())
                .map_err(QueryError::invalid)?,
        };
        Ok((kind, find))
    }
}

#[derive(Serialize, JsonSchema)]
struct Classes {
    classes: Vec<String>,
}
#[derive(Serialize, JsonSchema)]
struct Manifest {
    xml: String,
}
#[derive(Serialize, JsonSchema)]
struct References {
    references: Vec<Reference>,
}

fn tool<I: JsonSchema + 'static, O: JsonSchema + 'static>(
    name: &'static str,
    description: &'static str,
) -> Tool {
    Tool::new(name, description, serde_json::Map::new())
        .with_input_schema::<I>()
        .with_output_schema::<O>()
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        )
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool::<GetClass, ClassSource>(
            "getclass",
            "Decompile one class from a local APK. Accepts an absolute apk_path and a Dalvik descriptor or dotted class_name. Returns source, class_name and dex_name; missing classes are errors. No files are written.",
        ),
        tool::<ListClass, Classes>(
            "listclass",
            "List all classes in a local APK, optionally filtered by class/package prefix. Returns the complete classes array (Dalvik descriptors); no matches is an empty array. Requires an absolute apk_path. No pagination or file output.",
        ),
        tool::<GetManifest, Manifest>(
            "getmanifest",
            "Decode AndroidManifest.xml from a local APK. Requires an absolute apk_path. Returns the complete XML in xml; a missing or invalid manifest is an error. No files are written.",
        ),
        tool::<FindRefs, References>(
            "findrefs",
            "Find callers referencing a string, type, method or field across all DEX files in a local APK. query.kind selects the search; string/type use fuzzy value, method/field use fuzzy name and/or class_name with optional fuzzy_class. Returns complete structured references with dex_name, class_name, method_name and matched targets. Empty matches succeed; partial scan failures are errors. Requires an absolute apk_path.",
        ),
    ]
}

pub(super) enum Query {
    Class(GetClass),
    Classes(ListClass),
    Manifest(GetManifest),
    References(FindRefs),
}

impl Query {
    pub(super) fn parse(name: &str, args: Value) -> Result<Self, QueryError> {
        let result = match name {
            "getclass" => serde_json::from_value(args).map(Self::Class),
            "listclass" => serde_json::from_value(args).map(Self::Classes),
            "getmanifest" => serde_json::from_value(args).map(Self::Manifest),
            "findrefs" => serde_json::from_value(args).map(Self::References),
            _ => return Err(QueryError::invalid("unknown tool")),
        };
        result.map_err(|error| QueryError::invalid(error.to_string()))
    }

    pub(super) fn execute(self, threads: usize) -> Result<Value, QueryError> {
        match self {
            Self::Class(args) => {
                encode(ApkQuery::new(&args.apk_path, threads)?.getclass(&args.class_name)?)
            }
            Self::Classes(args) => encode(Classes {
                classes: ApkQuery::new(&args.apk_path, threads)?
                    .listclass(args.prefix.as_deref())?,
            }),
            Self::Manifest(args) => encode(Manifest {
                xml: ApkQuery::new(&args.apk_path, threads)?.getmanifest()?,
            }),
            Self::References(args) => {
                let (kind, find) = args.query.into_find()?;
                encode(References {
                    references: ApkQuery::new(&args.apk_path, threads)?.findrefs(kind, &find)?,
                })
            }
        }
    }
}

fn encode(value: impl Serialize) -> Result<Value, QueryError> {
    serde_json::to_value(value).map_err(|error| {
        QueryError::new(
            crate::asc_client::query::QueryErrorCode::QueryFailed,
            error.to_string(),
        )
    })
}

pub(super) fn error_result(error: QueryError) -> CallToolResult {
    CallToolResult::structured_error(json!({"code": error.code.as_str(), "message": error.message}))
}
