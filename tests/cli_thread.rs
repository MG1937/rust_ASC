use std::process::{Command, Output};

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rust_ASC"))
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn thread_option_is_singular_and_belongs_to_each_command() {
    for command in ["getclass", "listclass", "listmethod", "export", "findrefs"] {
        let output = run_cli(&[command, "--help"]);
        assert_eq!(output.status.code(), Some(1));
        let stderr = stderr(&output);
        assert!(stderr.contains("--thread <thread>"), "{command}: {stderr}");
        assert!(!stderr.contains("--threads"), "{command}: {stderr}");
    }
}

#[test]
fn mcp_command_follows_the_compile_time_feature() {
    let output = run_cli(&["mcp", "--help"]);
    let text = stderr(&output);
    if cfg!(feature = "mcp") {
        assert!(text.contains("Serve MCP tools over stdio."), "{text}");
    } else {
        assert!(text.contains("unrecognized subcommand 'mcp'"), "{text}");
    }
}

#[test]
fn plural_threads_option_is_rejected() {
    let output = run_cli(&[
        "findrefs",
        "--threads",
        "2",
        "fixture.apk",
        "string",
        "value",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("unexpected argument '--threads'"));
}
