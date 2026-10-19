#![cfg(feature = "mcp")]

mod dex_fixture;
mod zip_fixture;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dex_fixture::{
    make_class_only_dex, make_dex, make_dex041_container, make_instance_field_dex, make_invoke_dex,
};
use serde_json::{Value, json};
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Result<Value, String>>,
    stdout: Option<JoinHandle<()>>,
    stderr: Option<JoinHandle<String>>,
}

impl Client {
    fn new() -> Self {
        Self::version("2025-11-25")
    }

    fn version(version: &str) -> Self {
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
                let result = line.map_err(|e| e.to_string()).and_then(|line| {
                    serde_json::from_str(&line)
                        .map_err(|e| format!("non-protocol stdout: {line}: {e}"))
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
        };
        client.send(json!({"jsonrpc":"2.0", "id":0, "method":"initialize", "params":{
            "protocolVersion":version, "capabilities":{}, "clientInfo":{"name":"test", "version":"1"}
        }}));
        let response = client.recv();
        assert_eq!(response["id"], 0);
        assert_eq!(response["result"]["protocolVersion"], version, "{response}");
        assert!(
            response["result"]["capabilities"]["tools"].is_object(),
            "{response}"
        );
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
            .recv_timeout(Duration::from_secs(20))
            .expect("MCP reply timeout/disconnect")
            .expect("stdout must contain only JSON-RPC")
    }

    fn call(&mut self, name: &str, args: Value) -> Value {
        self.send(
            json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
                "name":name, "arguments":args
            }}),
        );
        let response = self.recv();
        assert_eq!(response["id"], 1, "{response}");
        assert!(response.get("error").is_none(), "{response}");
        let result = &response["result"];
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, result["structuredContent"]);
        result.clone()
    }

    fn error(&mut self, name: &str, args: Value, code: &str) {
        let result = self.call(name, args);
        assert_eq!(result["isError"], true, "{result}");
        assert_eq!(result["structuredContent"]["code"], code, "{result}");
        assert!(
            !result["structuredContent"]["message"]
                .as_str()
                .unwrap()
                .is_empty()
        );
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
        if let Some(remaining) = self.output.try_iter().next() {
            panic!("unexpected trailing protocol output: {remaining:?}");
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn success(result: &Value) -> &Value {
    assert_eq!(result["isError"], false, "{result}");
    &result["structuredContent"]
}

#[test]
fn discovers_exactly_four_read_only_typed_tools_and_supports_legacy_clients() {
    for version in ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"] {
        let mut client = Client::version(version);
        client.send(json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"}));
        let response = client.recv();
        let tools = response["result"]["tools"].as_array().unwrap();
        let mut names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        names.sort();
        assert_eq!(names, ["findrefs", "getclass", "getmanifest", "listclass"]);
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object");
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            assert_eq!(tool["outputSchema"]["type"], "object");
            assert_eq!(tool["annotations"]["readOnlyHint"], true);
            assert_eq!(tool["annotations"]["openWorldHint"], false);
        }
        client.send(json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":"export","arguments":{}}}));
        assert_eq!(client.recv()["error"]["code"], -32602);
        client.finish();
    }
}

#[test]
fn four_queries_return_full_structured_data_and_do_not_write_files() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    let dex = make_dex();
    let manifest = minimal_manifest();
    write_apk(
        &apk,
        &[("classes.dex", &dex), ("AndroidManifest.xml", &manifest)],
        CompressionMethod::Deflated,
    );
    let mut client = Client::new();
    let result = client.call("listclass", json!({"apk_path":apk}));
    assert_eq!(success(&result)["classes"], json!(["Lexample/Test;"]));
    let result = client.call(
        "getclass",
        json!({"apk_path":apk,"class_name":"example.Test"}),
    );
    let data = success(&result);
    assert_eq!(data["class_name"], "Lexample/Test;");
    assert_eq!(data["dex_name"], "classes.dex");
    assert!(data["source"].as_str().unwrap().contains("class Test"));
    let result = client.call("getmanifest", json!({"apk_path":apk}));
    assert!(
        success(&result)["xml"]
            .as_str()
            .unwrap()
            .contains("<manifest")
    );
    let result = client.call(
        "findrefs",
        json!({"apk_path":apk,"query":{"kind":"string","value":"token"}}),
    );
    let expected = ["first", "second"].map(|name| {
        json!({
            "dex_name":"classes.dex", "class_name":"Lexample/Test;",
            "method_name":name, "matched":["token"]
        })
    });
    assert_eq!(success(&result)["references"], json!(expected));
    let cli = Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .args(["findrefs", apk.to_str().unwrap(), "string", "token"])
        .output()
        .unwrap();
    assert!(cli.status.success());
    assert_eq!(
        String::from_utf8(cli.stdout).unwrap(),
        "classes.dex | Lexample/Test;->first | matched=(token)\nclasses.dex | Lexample/Test;->second | matched=(token)\n"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    client.finish();
}

#[test]
fn failures_are_tool_errors_but_no_matches_are_successful() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    write_apk(
        &apk,
        &[("classes.dex", &make_dex())],
        CompressionMethod::Stored,
    );
    let mut client = Client::new();
    client.error(
        "listclass",
        json!({"apk_path":"relative.apk"}),
        "INVALID_ARGUMENT",
    );
    client.error(
        "listclass",
        json!({"apk_path":dir.path()}),
        "INVALID_ARGUMENT",
    );
    client.error(
        "listclass",
        json!({"apk_path":dir.path().join("missing.apk")}),
        "FILE_NOT_FOUND",
    );
    client.error(
        "listclass",
        json!({"apk_path":apk,"prefix":" "}),
        "INVALID_ARGUMENT",
    );
    client.error(
        "listclass",
        json!({"apk_path":apk,"output":"not-allowed"}),
        "INVALID_ARGUMENT",
    );
    client.error("getclass", json!({"apk_path":apk}), "INVALID_ARGUMENT");
    client.error(
        "getclass",
        json!({"apk_path":apk,"class_name":"not.Found"}),
        "NOT_FOUND",
    );
    client.error("getmanifest", json!({"apk_path":apk}), "NOT_FOUND");
    client.error(
        "findrefs",
        json!({"apk_path":apk,"query":{"kind":"method"}}),
        "INVALID_ARGUMENT",
    );
    client.error(
        "findrefs",
        json!({"apk_path":apk,"query":{"kind":"invalid"}}),
        "INVALID_ARGUMENT",
    );
    let result = client.call("listclass", json!({"apk_path":apk,"prefix":"missing"}));
    assert_eq!(success(&result)["classes"], json!([]));
    let result = client.call(
        "findrefs",
        json!({"apk_path":apk,"query":{"kind":"string","value":"missing"}}),
    );
    assert_eq!(success(&result)["references"], json!([]));
    client.finish();
}

#[test]
fn malformed_inputs_are_not_reported_as_empty_or_partial_success() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    let mut client = Client::new();
    for bytes in [b"not a zip".as_slice(), b""] {
        std::fs::write(&apk, bytes).unwrap();
        client.error("listclass", json!({"apk_path":apk}), "INVALID_FORMAT");
        client.error(
            "getclass",
            json!({"apk_path":apk,"class_name":"example.Test"}),
            "INVALID_FORMAT",
        );
    }
    write_apk(
        &apk,
        &[("classes.dex", &make_dex()), ("classes2.dex", b"not a dex")],
        CompressionMethod::Deflated,
    );
    client.error(
        "findrefs",
        json!({"apk_path":apk,"query":{"kind":"string","value":"token"}}),
        "INVALID_FORMAT",
    );
    client.error("listclass", json!({"apk_path":apk}), "INVALID_FORMAT");
    let mut bad_strings = make_dex();
    let string_ids = dex_fixture::get_u32(&bad_strings, 0x3c) as usize;
    dex_fixture::put_u32(&mut bad_strings, string_ids, u32::MAX);
    write_apk(
        &apk,
        &[("classes.dex", &bad_strings)],
        CompressionMethod::Stored,
    );
    client.error(
        "findrefs",
        json!({"apk_path":apk,"query":{"kind":"string","value":"token"}}),
        "INVALID_FORMAT",
    );
    let mut broken_container = make_dex041_container();
    broken_container.truncate(broken_container.len() - 8);
    write_apk(
        &apk,
        &[("classes.dex", &broken_container)],
        CompressionMethod::Stored,
    );
    client.error("listclass", json!({"apk_path":apk}), "INVALID_FORMAT");
    write_apk(
        &apk,
        &[("AndroidManifest.xml", b"bad xml")],
        CompressionMethod::Stored,
    );
    client.error("getmanifest", json!({"apk_path":apk}), "INVALID_FORMAT");
    // A well-formed archive without DEX files is not a malformed archive.
    let result = client.call("listclass", json!({"apk_path":apk}));
    assert_eq!(success(&result)["classes"], json!([]));
    // Corrupt the central-directory byte count, keeping the EOCD present.
    let mut data = std::fs::read(&apk).unwrap();
    let offset = data.len() - 22 + 12;
    dex_fixture::put_u32(&mut data, offset, u32::MAX);
    std::fs::write(&apk, data).unwrap();
    client.error("listclass", json!({"apk_path":apk}), "INVALID_FORMAT");
    client.finish();
}

#[test]
fn repeated_calls_observe_new_files_and_multidex041_is_preserved() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    let mut client = Client::new();
    write_apk(
        &apk,
        &[("classes.dex", &make_dex())],
        CompressionMethod::Stored,
    );
    let result = client.call("listclass", json!({"apk_path":apk}));
    assert_eq!(success(&result)["classes"], json!(["Lexample/Test;"]));
    write_apk(
        &apk,
        &[("classes.dex", &make_dex041_container())],
        CompressionMethod::Deflated,
    );
    let result = client.call("listclass", json!({"apk_path":apk}));
    assert_eq!(
        success(&result)["classes"],
        json!([
            "Lalpha/First;",
            "Lshared/Duplicate;",
            "Lbeta/Second;",
            "Lshared/Duplicate;"
        ])
    );
    let result = client.call(
        "getclass",
        json!({"apk_path":apk,"class_name":"beta.Second"}),
    );
    assert_eq!(success(&result)["dex_name"], "classes.dex!classes2.dex");
    client.finish();
}

#[test]
fn all_reference_kinds_have_structured_results() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    let mut client = Client::new();
    let mut invoke_dex = make_invoke_dex();
    // Make the call self-referential. The shared fixture's trailing Target
    // type is unsorted; Test is searchable by the exact-class binary search.
    let methods = dex_fixture::get_u32(&invoke_dex, 0x5c) as usize;
    invoke_dex[methods + 8..methods + 10].copy_from_slice(&0u16.to_le_bytes());
    let mut type_dex = make_dex();
    // Replace const-string v0, token with const-class v0, Lexample/Test;.
    let instruction = type_dex
        .windows(6)
        .position(|bytes| bytes == b"\x1a\0\x05\0\x0e\0")
        .unwrap();
    type_dex[instruction..instruction + 4].copy_from_slice(b"\x1c\0\0\0");
    write_apk(
        &apk,
        &[
            ("classes.dex", &invoke_dex),
            ("classes2.dex", &make_instance_field_dex()),
            ("classes3.dex", &type_dex),
        ],
        CompressionMethod::Stored,
    );
    for query in [
        json!({"kind":"type","value":"example"}),
        json!({"kind":"method","name":"callToMethod","class_name":"example.Test"}),
        json!({"kind":"method","name":"callToMethod","class_name":"Test","fuzzy_class":true}),
        json!({"kind":"field","name":"a","class_name":"example.Test"}),
    ] {
        let result = client.call("findrefs", json!({"apk_path":apk,"query":query}));
        let references = success(&result)["references"].as_array().unwrap();
        assert!(!references.is_empty(), "{query}: {result}");
        for reference in references {
            assert!(!reference["matched"].as_array().unwrap().is_empty());
            assert!(
                reference["dex_name"]
                    .as_str()
                    .unwrap()
                    .starts_with("classes")
            );
        }
    }
    client.finish();
}

#[test]
fn concurrent_requests_have_independent_ids_and_complete_untruncated_results() {
    let dir = tempdir().unwrap();
    let apk = dir.path().join("fixture.apk");
    let names: Vec<_> = (0..4000)
        .map(|i| format!("Lexample/Class{i:04};"))
        .collect();
    let descriptors: Vec<_> = names.iter().map(String::as_str).collect();
    let dex = make_class_only_dex(&descriptors, 0, b"035");
    write_apk(&apk, &[("classes.dex", &dex)], CompressionMethod::Deflated);
    let mut client = Client::new();
    for id in 1..=8 {
        client.send(
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                "name":"listclass","arguments":{"apk_path":apk}
            }}),
        );
    }
    client.send(json!({"jsonrpc":"2.0","id":9,"method":"ping"}));
    let mut results = BTreeMap::new();
    for _ in 1..=9 {
        let response = client.recv();
        assert!(
            results
                .insert(response["id"].as_u64().unwrap(), response)
                .is_none()
        );
    }
    for id in 1..=8 {
        let result = &results[&id]["result"];
        assert_eq!(success(result)["classes"], json!(names));
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, result["structuredContent"]);
    }
    assert!(results[&9].get("error").is_none());
    client.finish();
}

// Minimal valid binary XML: one UTF-8 string, an empty resource map, and a
// manifest start/end pair. Kept generated and reviewable instead of a binary blob.
fn minimal_manifest() -> Vec<u8> {
    fn u16_(out: &mut Vec<u8>, n: u16) {
        out.extend(n.to_le_bytes());
    }
    fn u32_(out: &mut Vec<u8>, n: u32) {
        out.extend(n.to_le_bytes());
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
