#![cfg(feature = "mcp")]

mod dex_fixture;
mod zip_fixture;

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dex_fixture::{make_dex, make_instance_field_dex, make_invoke_dex};
use serde_json::{Value, json};
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Result<Value, String>>,
    stdout: Option<JoinHandle<()>>,
    stderr: Option<JoinHandle<String>>,
    next_id: u64,
}

impl Client {
    fn new() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let stderr = std::thread::spawn(move || {
            let mut text = String::new();
            stderr.read_to_string(&mut text).unwrap();
            text
        });
        let (send, output) = mpsc::channel();
        let stdout = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let result = line.map_err(|error| error.to_string()).and_then(|line| {
                    serde_json::from_str(&line)
                        .map_err(|error| format!("non-protocol stdout: {line}: {error}"))
                });
                if send.send(result).is_err() {
                    break;
                }
            }
        });
        let mut client = Self {
            child,
            input,
            output,
            stdout: Some(stdout),
            stderr: Some(stderr),
            next_id: 1,
        };
        client.send(
            json!({"jsonrpc":"2.0", "id":0, "method":"initialize", "params":{
                "protocolVersion":"2025-11-25",
                "capabilities":{},
                "clientInfo":{"name":"test", "version":"1"}
            }}),
        );
        let response = client.recv();
        assert_eq!(response["id"], 0);
        assert_eq!(response["result"]["serverInfo"]["name"], "rust_ASC");
        client.send(json!({"jsonrpc":"2.0", "method":"notifications/initialized"}));
        client
    }

    fn send(&mut self, value: Value) {
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{value}").unwrap();
        input.flush().unwrap();
    }

    fn recv(&self) -> Value {
        self.output
            .recv_timeout(Duration::from_secs(30))
            .expect("MCP reply timeout/disconnect")
            .expect("stdout must contain only JSON-RPC")
    }

    fn call(&mut self, name: &str, args: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(
            json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":{
                "name":name, "arguments":args
            }}),
        );
        let response = self.recv();
        assert_eq!(response["id"], id, "{response}");
        assert!(response.get("error").is_none(), "{response}");
        response["result"].clone()
    }

    fn finish(mut self) {
        self.input.take();
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let stderr = self.stderr.take().unwrap().join().unwrap();
                assert!(status.success(), "MCP exit: {status}; {stderr}");
                assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "MCP did not exit on EOF"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        self.stdout.take().unwrap().join().unwrap();
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn text(result: &Value) -> &str {
    result["content"][0]["text"].as_str().unwrap()
}

fn run_cli(args: impl IntoIterator<Item = OsString>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .args(args)
        .output()
        .unwrap()
}

fn cli_stdout(args: impl IntoIterator<Item = OsString>) -> String {
    let output = run_cli(args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn exposes_four_documented_cli_wrappers() {
    let mut client = Client::new();
    client.send(json!({"jsonrpc":"2.0", "id":99, "method":"tools/list"}));
    let response = client.recv();
    let tools = response["result"]["tools"].as_array().unwrap();
    let mut names: Vec<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["findrefs", "getclass", "getmanifest", "listclass"]);
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        assert_eq!(tool["annotations"]["readOnlyHint"], false);
        assert_eq!(tool["annotations"]["destructiveHint"], true);
        assert!(tool.get("outputSchema").is_none());
        let description = tool["description"].as_str().unwrap();
        assert!(
            (20..=80).contains(&description.len()),
            "tool description is not concise: {description}"
        );
        for forbidden in ["-", "—", "{", "apk_path", "class_name", "fuzzy_class"] {
            assert!(
                !description.contains(forbidden),
                "tool description contains {forbidden}: {description}"
            );
        }
        assert_described_properties(&tool["inputSchema"]);
        assert_concise_descriptions(&tool["inputSchema"]);
        let output = tool["inputSchema"]["properties"]["output"]["description"]
            .as_str()
            .unwrap();
        if tool["name"] == "listclass" {
            assert!(output.contains("Returned text is empty."));
        } else {
            assert!(output.contains("Content is also returned."));
        }
    }
    client.send(
        json!({"jsonrpc":"2.0", "id":100, "method":"tools/call", "params":{
            "name":"export", "arguments":{}
        }}),
    );
    assert_eq!(client.recv()["error"]["code"], -32602);
    client.finish();
}

fn assert_described_properties(schema: &Value) {
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            if name != "kind" {
                assert!(
                    property
                        .get("description")
                        .and_then(Value::as_str)
                        .is_some_and(|description| !description.is_empty()),
                    "parameter {name} has no description: {property}"
                );
            }
        }
    }
    if let Some(object) = schema.as_object() {
        for value in object.values() {
            assert_described_properties(value);
        }
    } else if let Some(array) = schema.as_array() {
        for value in array {
            assert_described_properties(value);
        }
    }
}

fn assert_concise_descriptions(schema: &Value) {
    if let Some(object) = schema.as_object() {
        if let Some(description) = object.get("description").and_then(Value::as_str) {
            assert!(
                description.len() <= 120,
                "description is too long: {description}"
            );
            assert!(
                !description.contains('-') && !description.contains('—'),
                "description contains a dash: {description}"
            );
        }
        for value in object.values() {
            assert_concise_descriptions(value);
        }
    } else if let Some(array) = schema.as_array() {
        for value in array {
            assert_concise_descriptions(value);
        }
    }
}

#[test]
fn tool_results_are_exact_cli_stdout() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture with space.apk");
    let dex = make_dex();
    let manifest = minimal_manifest();
    write_apk(
        &apk,
        &[("classes.dex", &dex), ("AndroidManifest.xml", &manifest)],
        CompressionMethod::Deflated,
    );
    let path = apk.to_string_lossy().into_owned();
    let mut client = Client::new();

    let result = client.call(
        "listclass",
        json!({"apk_path":path, "prefix":"example", "thread":1}),
    );
    assert_eq!(result["isError"], false);
    assert_eq!(
        text(&result),
        cli_stdout(
            ["listclass", "--thread", "1", "--prefix", "example", &path,].map(OsString::from)
        )
    );

    let result = client.call(
        "getclass",
        json!({"apk_path":path, "class_name":"example.Test", "thread":1}),
    );
    assert_eq!(result["isError"], false);
    assert_eq!(
        text(&result),
        cli_stdout(["getclass", "--thread", "1", &path, "example.Test"].map(OsString::from))
    );

    let result = client.call("getmanifest", json!({"apk_path":path}));
    assert_eq!(result["isError"], false);
    assert_eq!(
        text(&result),
        cli_stdout(["getmanifest", &path].map(OsString::from))
    );

    let result = client.call(
        "findrefs",
        json!({
            "apk_path":path,
            "thread":1,
            "query":{"kind":"string", "value":"token"}
        }),
    );
    assert_eq!(result["isError"], false);
    assert_eq!(
        text(&result),
        cli_stdout(["findrefs", "--thread", "1", &path, "string", "token"].map(OsString::from))
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    client.finish();
}

#[test]
fn optional_output_writes_files_with_cli_semantics() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    let dex = make_dex();
    let manifest = minimal_manifest();
    write_apk(
        &apk,
        &[("classes.dex", &dex), ("AndroidManifest.xml", &manifest)],
        CompressionMethod::Deflated,
    );
    let path = apk.to_string_lossy().into_owned();
    let mut client = Client::new();

    let class_output = dir.path().join("Test.java");
    let result = client.call(
        "getclass",
        json!({
            "apk_path":path,
            "class_name":"example.Test",
            "thread":1,
            "output":class_output
        }),
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(
        std::fs::read_to_string(&class_output).unwrap().trim_end(),
        text(&result).trim_end()
    );

    let classes_output = dir.path().join("classes.txt");
    let result = client.call(
        "listclass",
        json!({"apk_path":path, "thread":1, "output":classes_output}),
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(
        std::fs::read_to_string(&classes_output).unwrap(),
        "Lexample/Test;\n"
    );
    assert_eq!(text(&result), "");

    let manifest_output = dir.path().join("AndroidManifest.xml");
    let result = client.call(
        "getmanifest",
        json!({"apk_path":path, "output":manifest_output}),
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(
        std::fs::read_to_string(&manifest_output)
            .unwrap()
            .trim_end(),
        text(&result).trim_end()
    );

    let refs_output = dir.path().join("references.txt");
    let result = client.call(
        "findrefs",
        json!({
            "apk_path":path,
            "thread":1,
            "query":{"kind":"string", "value":"token"},
            "output":refs_output
        }),
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(
        std::fs::read_to_string(&refs_output).unwrap(),
        text(&result)
    );
    client.finish();
}

#[test]
fn findrefs_query_variants_map_to_cli_arguments() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("references.apk");
    let mut type_dex = make_dex();
    let instruction = type_dex
        .windows(6)
        .position(|bytes| bytes == b"\x1a\0\x05\0\x0e\0")
        .unwrap();
    type_dex[instruction..instruction + 4].copy_from_slice(b"\x1c\0\0\0");
    write_apk(
        &apk,
        &[
            ("classes.dex", &type_dex),
            ("classes2.dex", &make_invoke_dex()),
            ("classes3.dex", &make_instance_field_dex()),
        ],
        CompressionMethod::Stored,
    );
    let path = apk.to_string_lossy().into_owned();
    let mut client = Client::new();
    let cases = [
        (
            json!({"kind":"type", "value":"example"}),
            vec!["type", "example"],
        ),
        (
            json!({
                "kind":"method",
                "name":"callToMethod",
                "class_name":"example.Target"
            }),
            vec!["method", "callToMethod", "--class", "example.Target"],
        ),
        (
            json!({
                "kind":"field",
                "name":"a",
                "class_name":"example",
                "fuzzy_class":true
            }),
            vec!["field", "a", "--class", "example", "--fuzzy-class"],
        ),
    ];
    for (query, query_args) in cases {
        let result = client.call("findrefs", json!({"apk_path":path, "query":query}));
        assert_eq!(result["isError"], false, "{result}");
        let mut cli_args = vec![OsString::from("findrefs"), OsString::from(&path)];
        cli_args.extend(query_args.into_iter().map(OsString::from));
        assert_eq!(text(&result), cli_stdout(cli_args));
    }
    client.finish();
}

#[test]
fn cli_failures_are_isolated_and_the_server_remains_usable() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    write_apk(
        &apk,
        &[("classes.dex", &make_dex())],
        CompressionMethod::Stored,
    );
    let path = apk.to_string_lossy().into_owned();
    let mut client = Client::new();

    let result = client.call("getclass", json!({"apk_path":path}));
    assert_eq!(result["isError"], true);
    assert!(text(&result).contains("invalid arguments"), "{result}");

    let cli = run_cli(
        ["getclass", &path, "example.Missing"]
            .map(OsString::from)
            .into_iter(),
    );
    assert!(!cli.status.success());
    let result = client.call(
        "getclass",
        json!({"apk_path":path, "class_name":"example.Missing"}),
    );
    assert_eq!(result["isError"], true);
    assert_eq!(text(&result), String::from_utf8_lossy(&cli.stderr).trim());

    let result = client.call("listclass", json!({"apk_path":path}));
    assert_eq!(result["isError"], false);
    assert_eq!(text(&result), "Lexample/Test;\n");
    client.finish();
}

fn minimal_manifest() -> Vec<u8> {
    fn u16_(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_le_bytes());
    }
    fn u32_(out: &mut Vec<u8>, value: u32) {
        out.extend(value.to_le_bytes());
    }
    fn header(out: &mut Vec<u8>, kind: u16, header_size: u16, size: u32) {
        u16_(out, kind);
        u16_(out, header_size);
        u32_(out, size);
    }

    let mut out = Vec::new();
    header(&mut out, 3, 8, 120);
    header(&mut out, 1, 28, 44);
    for value in [1, 0, 0x100, 32, 0, 0] {
        u32_(&mut out, value);
    }
    out.extend(b"\x08\x08manifest\0\0");
    header(&mut out, 0x180, 8, 8);
    header(&mut out, 0x102, 16, 36);
    for value in [1, u32::MAX, u32::MAX, 0] {
        u32_(&mut out, value);
    }
    for value in [20, 20, 0, 0, 0, 0] {
        u16_(&mut out, value);
    }
    header(&mut out, 0x103, 16, 24);
    for value in [1, u32::MAX, u32::MAX, 0] {
        u32_(&mut out, value);
    }
    assert_eq!(out.len(), 120);
    out
}
