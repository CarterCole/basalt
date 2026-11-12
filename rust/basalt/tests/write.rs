//! The write surfaces end to end, PROTOCOL §12.7: `basalt mcp --writable`
//! over stdio and `basalt add`, through the real binary.

mod support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use support::conformance_dir;

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Tmp {
    let d = std::env::temp_dir().join(format!("basalt-write-{}-{}", std::process::id(), basalt::ulid()));
    copy_dir(&conformance_dir().join("vaults/minimal/vault"), &d);
    Tmp(d)
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

fn basalt(args: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_basalt"))
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = child.wait_with_output().unwrap();
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
}

/// The tool-result text of each `tools/call` response, by request id.
fn tool_text(stdout: &str, id: i64) -> (bool, String) {
    for line in stdout.lines() {
        let j = basalt::canonical::parse_json(line).unwrap();
        if j.get("id") == Some(&basalt::Json::Int(id)) {
            let r = j.get("result").unwrap();
            let is_error = r.get("isError") == Some(&basalt::Json::Bool(true));
            let text = r.get("content").unwrap().as_array().unwrap()[0].get("text").unwrap().as_str().unwrap().to_string();
            return (is_error, text);
        }
    }
    panic!("no response {id} in {stdout}");
}

const INIT: &str = r##"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"test-client","version":"9.9"}}}"##;

#[test]
fn a_read_only_server_neither_lists_nor_accepts_basalt_store() {
    let v = scratch();
    let dir = v.0.to_str().unwrap();
    let call = r##"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"basalt_store","arguments":{"path":"Notes/X.md","text":"x"}}}"##;
    let (ok, out, _) = basalt(&["mcp", "--vault", dir, "--principal", "u:editor"], &format!("{INIT}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n{call}\n"));
    assert!(ok);
    let listed = out.lines().find(|l| l.contains("\"id\":2")).unwrap();
    assert!(!listed.contains("basalt_store"), "{listed}");
    assert!(out.contains("unknown tool basalt_store"), "{out}");
    assert!(!v.0.join("content/Notes/X.md").exists());
}

#[test]
fn a_writable_server_stores_and_stamps_who_was_behind_it() {
    let v = scratch();
    let dir = v.0.to_str().unwrap();
    let note = r##"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"basalt_store","arguments":{"path":"Notes/From MCP.md","text":"# From MCP\n\nSee [[Hexes]].\n"}}}"##;
    // An editor has no create_child on Assets/, so the image goes in Notes/.
    let image = r##"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"basalt_store","arguments":{"path":"Notes/dot.png","base64":"iVBORw0KGgo=","alt":"A dot"}}}"##;
    let again = r##"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"basalt_store","arguments":{"path":"Notes/From MCP.md","text":"again"}}}"##;
    let read = r##"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"basalt_node","arguments":{"path":"Notes/From MCP.md"}}}"##;
    let input = format!("{INIT}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n{note}\n{image}\n{again}\n{read}\n");
    let (ok, out, err) = basalt(
        &["mcp", "--vault", dir, "--principal", "u:editor", "--writable", "--agent", "claude-code", "--account", "work"],
        &input,
    );
    assert!(ok, "{err}");
    assert!(err.contains("may create notes") && err.contains("agent claude-code"), "{err}");
    assert!(out.contains("\"basalt_store\""), "listed: {out}");

    let (is_err, text) = tool_text(&out, 3);
    assert!(!is_err, "{text}");
    assert!(text.contains("\"link\": \"[[Notes/From MCP]]\""), "{text}");
    let stored = std::fs::read_to_string(v.0.join("content/Notes/From MCP.md")).unwrap();
    for want in ["principal: u:editor", "agent: claude-code", "account: work", "name: test-client", "version: \"9.9\""] {
        assert!(stored.contains(want), "{want} in {stored}");
    }

    let (is_err, text) = tool_text(&out, 4);
    assert!(!is_err, "{text}");
    assert!(text.contains("\"link\": \"![[Notes/dot.png]]\""), "{text}");

    let (is_err, text) = tool_text(&out, 5);
    assert!(is_err);
    assert!(text.contains("\"error\": \"conflict\"") && text.contains("never overwrite"), "{text}");

    let (is_err, text) = tool_text(&out, 6);
    assert!(!is_err, "the vault reads it back: {text}");
}

#[test]
fn writable_needs_a_principal_and_labels_need_writable() {
    let v = scratch();
    let dir = v.0.to_str().unwrap();
    let (ok, _, err) = basalt(&["mcp", "--vault", dir, "--writable"], "");
    assert!(!ok && err.contains("--writable needs --principal"), "{err}");
    let (ok, _, err) = basalt(&["mcp", "--vault", dir, "--agent", "x"], "");
    assert!(!ok && err.contains("need --writable"), "{err}");
    let (ok, _, err) = basalt(&["mcp", "--vault", dir, "--principal", "u:carter", "--writable", "--agent", "me@example.com"], "");
    assert!(!ok && err.contains("short label"), "{err}");
}

#[test]
fn add_stores_a_note_an_image_and_stdin_then_refuses_a_repeat() {
    let v = scratch();
    let dir = v.0.to_str().unwrap();
    let src = scratch();
    let note = src.0.join("Idea.md");
    let png = src.0.join("dot.png");
    std::fs::write(&note, "# Idea\n").unwrap();
    std::fs::write(&png, [0x89, 0x50, 0x4e, 0x47, 0xff]).unwrap();

    let (ok, out, err) = basalt(&["add", note.to_str().unwrap(), png.to_str().unwrap(), "--vault", dir, "--agent", "cli"], "");
    assert!(ok, "{out}{err}");
    assert!(v.0.join("content/Notes/Idea.md").exists());
    assert_eq!(std::fs::read(v.0.join("content/Assets/dot.png")).unwrap(), [0x89, 0x50, 0x4e, 0x47, 0xff]);
    let sc = std::fs::read_to_string(v.0.join("meta/folders/Assets/entries.yaml")).unwrap();
    assert!(sc.contains("diagram.png") && sc.contains("dot.png") && sc.contains("agent: cli"), "{sc}");
    let nodes = std::fs::read_to_string(v.0.join("index/nodes.json")).unwrap();
    assert!(nodes.contains("Notes/Idea.md") && nodes.contains("Assets/dot.png"));

    let (ok, _, err) = basalt(&["add", "-", "--as", "Notes/Piped.md", "--title", "Piped", "--vault", dir], "body\n");
    assert!(ok, "{err}");
    let piped = std::fs::read_to_string(v.0.join("content/Notes/Piped.md")).unwrap();
    assert!(piped.contains("title: Piped") && !piped.contains("created_by"), "{piped}");

    let (ok, _, err) = basalt(&["add", note.to_str().unwrap(), "--vault", dir], "");
    assert!(!ok && err.contains("refused") && err.contains("already exists"), "{err}");

    let (ok, _, err) = basalt(&["add", note.to_str().unwrap(), "--to", "Assets/", "--vault", dir, "--principal", "u:editor"], "");
    assert!(!ok && err.contains("forbidden"), "{err}");
}
