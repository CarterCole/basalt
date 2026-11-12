//! Folders to and from GitHub gists: the name mapping from the corpus, the API
//! client, `gist export` and `gist import`, and a whole vault living in a gist.
//!
//! Everything talks to a local stand-in for the gist API (the `Server` below,
//! std only), so no test touches the network or anyone's GitHub account. It is
//! deliberately stricter than it needs to be where GitHub's behaviour is the
//! reason for a rule in the code under test: a file name with a "/" is
//! refused, an empty file is refused, a write without the right token is a
//! 401, deleting a file the gist does not have is a 422, and a file over
//! `truncate_over` bytes is listed without its content.
//!
//! The same scenarios run in `ts/test/gist.test.mjs` and the Python suite, and
//! the corpus case file (`conformance/cases/gist/mapping.yaml`) is shared.

#![cfg(feature = "gist")]

mod support;

use basalt::gist::{collect, export_to_gist, import_from_gist, ExportArgs, ExportReport};
use basalt::serve::surface::base64_decode;
use basalt::store::{store_object, StoreRequest};
use basalt::transport::gist::{decode_name, encode_name, parse_gist_id, why_not_text};
use basalt::transport::{
    FsTransport, GistApi, GistTransport, ListOpts, PutMeta, Transport, TransportError,
};
use basalt::vault::Vault;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::{cases, conformance_dir, load, s, Report};

const TOKEN: &str = "test-token-not-a-real-secret";

// ------------------------------------------------------------- fake GitHub

#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    auth: Option<String>,
}

struct FakeGist {
    id: String,
    public: bool,
    description: String,
    updated_at: String,
    files: BTreeMap<String, String>,
}

struct Fake {
    gists: BTreeMap<String, FakeGist>,
    requests: Vec<Req>,
    truncate_over: usize,
    limit_reads: bool,
    counter: u64,
}

struct Server {
    url: String,
    addr: SocketAddr,
    fake: Arc<Mutex<Fake>>,
    stop: Arc<AtomicBool>,
}

fn urlenc(name: &str) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn urldec(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn view(g: &FakeGist, base: &str, truncate_over: usize) -> Value {
    let mut files = Map::new();
    for (name, content) in &g.files {
        let mut f = json!({
            "filename": name,
            "size": content.len(),
            "raw_url": format!("{base}/raw/{}/{}", g.id, urlenc(name)),
        });
        if content.len() > truncate_over {
            f["truncated"] = json!(true);
        } else {
            f["truncated"] = json!(false);
            f["content"] = json!(content);
        }
        files.insert(name.clone(), f);
    }
    json!({
        "id": g.id,
        "html_url": format!("https://gist.github.com/test/{}", g.id),
        "public": g.public,
        "description": g.description,
        "files": files,
        "updated_at": g.updated_at,
        "truncated": g.files.len() > 300,
    })
}

/// A file-map problem GitHub would answer with 422, or `None`.
fn bad_files(files: Option<&Value>, creating: bool) -> Option<String> {
    let obj = files?.as_object()?;
    for (name, f) in obj {
        if name.is_empty() || name.contains('/') {
            return Some(format!("file name {name:?} is not allowed"));
        }
        if f.is_null() {
            if creating {
                return Some("cannot delete in a create".into());
            }
            continue;
        }
        match f.get("content").and_then(Value::as_str) {
            Some(c) if !c.is_empty() => {}
            _ => return Some(format!("{name}: content is empty")),
        }
    }
    None
}

fn respond(s: &mut TcpStream, status: u16, body: &str, ctype: &str, extra: &[(&str, &str)]) {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body.as_bytes());
    let _ = s.flush();
}

fn json_reply(s: &mut TcpStream, status: u16, v: Value, extra: &[(&str, &str)]) {
    respond(s, status, &v.to_string(), "application/json", extra);
}

/// Method, target, lower-cased headers, body.
type Request = (String, String, BTreeMap<String, String>, Vec<u8>);

fn read_request(s: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p;
        }
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = BTreeMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((method, target, headers, body))
}

fn handle(mut s: TcpStream, fake: &Mutex<Fake>, base: &str) {
    let Some((method, target, headers, body)) = read_request(&mut s) else { return };
    let path = target.split('?').next().unwrap_or("").to_string();
    let auth = headers.get("authorization").cloned();
    let mut f = fake.lock().unwrap();
    f.requests.push(Req { method: method.clone(), path: path.clone(), auth: auth.clone() });
    let truncate_over = f.truncate_over;
    let body: Value = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap_or(Value::Null) };

    if method == "GET" && path.starts_with("/raw/") {
        let rest = &path["/raw/".len()..];
        let (id, name) = rest.split_once('/').unwrap_or((rest, ""));
        return match f.gists.get(id).and_then(|g| g.files.get(&urldec(name))) {
            Some(c) => respond(&mut s, 200, c, "text/plain", &[]),
            None => json_reply(&mut s, 404, json!({"message": "Not Found"}), &[]),
        };
    }
    if f.limit_reads && method == "GET" {
        return json_reply(
            &mut s,
            403,
            json!({"message": "API rate limit exceeded"}),
            &[("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "2000000000")],
        );
    }
    if method != "GET" && auth.as_deref() != Some(&format!("Bearer {TOKEN}")) {
        return json_reply(&mut s, 401, json!({"message": "Requires authentication"}), &[]);
    }
    if method == "POST" && path == "/gists" {
        if let Some(bad) = bad_files(body.get("files"), true) {
            return json_reply(&mut s, 422, json!({"message": format!("Validation Failed: {bad}")}), &[]);
        }
        let files: BTreeMap<String, String> = body
            .get("files")
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .map(|(n, v)| (n.clone(), v["content"].as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if files.is_empty() {
            return json_reply(&mut s, 422, json!({"message": "files are required"}), &[]);
        }
        if files.len() > 300 {
            return json_reply(&mut s, 422, json!({"message": "too many files"}), &[]);
        }
        f.counter += 1;
        let g = FakeGist {
            id: format!("{:032x}", 0xfeed_0000u64 + f.counter * 7919),
            public: body.get("public").and_then(Value::as_bool).unwrap_or(false),
            description: body.get("description").and_then(Value::as_str).unwrap_or("").to_string(),
            updated_at: format!("2026-01-01T00:00:{:02}Z", f.counter % 60),
            files,
        };
        let out = view(&g, base, truncate_over);
        f.gists.insert(g.id.clone(), g);
        return json_reply(&mut s, 201, out, &[]);
    }
    if let Some(id) = path.strip_prefix("/gists/") {
        let counter = f.counter;
        let Some(g) = f.gists.get_mut(id) else {
            return json_reply(&mut s, 404, json!({"message": "Not Found"}), &[]);
        };
        if method == "GET" {
            return json_reply(&mut s, 200, view(g, base, truncate_over), &[]);
        }
        if method == "PATCH" {
            if let Some(bad) = bad_files(body.get("files"), false) {
                return json_reply(&mut s, 422, json!({"message": format!("Validation Failed: {bad}")}), &[]);
            }
            let mut next = g.files.clone();
            if let Some(obj) = body.get("files").and_then(Value::as_object) {
                for (n, v) in obj {
                    if v.is_null() {
                        // GitHub answers an unknown file in a delete with 422,
                        // so the code under test must not send one.
                        if next.remove(n).is_none() {
                            return json_reply(&mut s, 422, json!({"message": format!("{n}: no such file")}), &[]);
                        }
                    } else {
                        next.insert(n.clone(), v["content"].as_str().unwrap_or("").to_string());
                    }
                }
            }
            if next.is_empty() {
                return json_reply(&mut s, 422, json!({"message": "a gist needs a file"}), &[]);
            }
            if next.len() > 300 {
                return json_reply(&mut s, 422, json!({"message": "too many files"}), &[]);
            }
            g.files = next;
            if let Some(d) = body.get("description").and_then(Value::as_str) {
                g.description = d.to_string();
            }
            g.updated_at = format!("2026-01-02T00:00:{:02}Z", (counter + 1) % 60);
            return json_reply(&mut s, 200, view(g, base, truncate_over), &[]);
        }
    }
    json_reply(&mut s, 404, json!({"message": "Not Found"}), &[]);
}

impl Server {
    fn start() -> Self {
        Self::with(1_000_000, false)
    }

    fn with(truncate_over: usize, limit_reads: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let fake = Arc::new(Mutex::new(Fake {
            gists: BTreeMap::new(),
            requests: Vec::new(),
            truncate_over,
            limit_reads,
            counter: 0,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        {
            let (fake, stop, base) = (fake.clone(), stop.clone(), url.clone());
            std::thread::spawn(move || {
                for conn in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(c) = conn else { continue };
                    let (fake, base) = (fake.clone(), base.clone());
                    std::thread::spawn(move || handle(c, &fake, &base));
                }
            });
        }
        Self { url, addr, fake, stop }
    }

    /// Put a gist there directly, as if someone had made it on the website.
    fn seed(&self, files: &[(&str, &str)]) -> String {
        let mut f = self.fake.lock().unwrap();
        f.counter += 1;
        let id = format!("{:032x}", 0xbeef_0000u64 + f.counter * 104729);
        let g = FakeGist {
            id: id.clone(),
            public: false,
            description: String::new(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            files: files.iter().map(|(n, c)| (n.to_string(), c.to_string())).collect(),
        };
        f.gists.insert(id.clone(), g);
        id
    }

    fn seed_many(&self, n: usize) -> String {
        let owned: Vec<(String, String)> = (0..n).map(|i| (format!("f{i}.md"), "x".to_string())).collect();
        let refs: Vec<(&str, &str)> = owned.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        self.seed(&refs)
    }

    fn requests(&self) -> Vec<Req> {
        self.fake.lock().unwrap().requests.clone()
    }

    fn count(&self, method: &str) -> usize {
        self.requests().iter().filter(|r| r.method == method).count()
    }

    fn files(&self, id: &str) -> BTreeMap<String, String> {
        self.fake.lock().unwrap().gists[id].files.clone()
    }

    fn put_file(&self, id: &str, name: &str, content: &str) {
        self.fake.lock().unwrap().gists.get_mut(id).unwrap().files.insert(name.into(), content.into());
    }

    fn description(&self, id: &str) -> String {
        self.fake.lock().unwrap().gists[id].description.clone()
    }

    fn only_gist(&self) -> String {
        let f = self.fake.lock().unwrap();
        assert_eq!(f.gists.len(), 1, "expected exactly one gist");
        f.gists.keys().next().unwrap().clone()
    }

    fn gist_count(&self) -> usize {
        self.fake.lock().unwrap().gists.len()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // wakes the accept loop
    }
}

// ----------------------------------------------------------------- helpers

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

fn fixture() -> PathBuf {
    conformance_dir().join("vaults/minimal/vault")
}

/// A scratch copy of the minimal vault, opened.
fn copy_of_vault() -> (Scratch, Vault) {
    let dir = std::env::temp_dir().join(format!("basalt-gist-{}-{}", std::process::id(), basalt::ulid()));
    copy_dir(&fixture(), &dir);
    let v = Vault::open(Box::new(FsTransport::new(&dir))).unwrap();
    (Scratch(dir), v)
}

fn authed(s: &Server) -> GistApi {
    GistApi::with_token(Some(&s.url), Some(TOKEN)).unwrap()
}

fn anon(s: &Server) -> GistApi {
    GistApi::with_token(Some(&s.url), None).unwrap()
}

fn files_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
}

fn export(v: &Vault, api: &GistApi, args: ExportArgs<'_>) -> Result<ExportReport, String> {
    export_to_gist(v, api, &args)
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn write(dir: &Scratch, rel: &str, bytes: &[u8]) {
    let p = dir.0.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn code_of(e: &basalt::transport::gist::GistError) -> &'static str {
    e.code
}

// ------------------------------------------------------------------ corpus

#[test]
fn the_gist_corpus_holds() {
    let doc = load("cases/gist/mapping.yaml");
    let all = cases(&doc);
    assert!(!all.is_empty());
    let mut r = Report::default();
    for c in &all {
        let name = s(c, "name").unwrap_or_default();
        match s(c, "kind").as_deref() {
            Some("name") => {
                let path = s(c, "path").unwrap();
                let file = s(c, "file").unwrap();
                r.check(&name, "encode", encode_name(&path), &file);
                r.check(&name, "decode", decode_name(&file), &path);
            }
            Some("decode") => {
                r.check(&name, "decode", decode_name(&s(c, "file").unwrap()), s(c, "path").unwrap());
            }
            Some("id") => {
                r.check(&name, "gist id", parse_gist_id(&s(c, "input").unwrap_or_default()), s(c, "id"));
            }
            Some("eligible") => {
                let bytes = match s(c, "base64") {
                    Some(b) => base64_decode(&b).expect("valid base64 in the corpus"),
                    None => s(c, "text").unwrap_or_default().into_bytes(),
                };
                let want = if support::b(c, "ok") == Some(true) { None } else { Some(s(c, "reason").unwrap()) };
                r.check(&name, "why not text", why_not_text(&bytes).map(str::to_string), want);
            }
            other => panic!("unknown gist case kind {other:?} in {name}"),
        }
    }
    r.finish("gist mapping");
}

// ------------------------------------------------------------------ client

#[test]
fn client_a_new_gist_is_secret_unless_asked_and_carries_the_description() {
    let s = Server::start();
    let one = files_of(&[("a.md", "hi")]);
    let a = authed(&s).create(&one, "notes", false).unwrap();
    assert!(!a.public);
    assert_eq!(s.description(&a.id), "notes");
    let b = authed(&s).create(&one, "", true).unwrap();
    assert!(b.public);
}

#[test]
fn client_writing_without_a_token_fails_before_any_request_is_made() {
    let s = Server::start();
    let e = anon(&s).create(&files_of(&[("a.md", "hi")]), "", false).unwrap_err();
    assert_eq!(code_of(&e), "no_token");
    assert!(e.message.contains("GITHUB_TOKEN"), "{e}");
    assert_eq!(s.requests().len(), 0);
}

#[test]
fn client_a_wrong_token_is_reported_as_one_and_a_missing_gist_as_missing() {
    let s = Server::start();
    let bad = GistApi::with_token(Some(&s.url), Some("nope")).unwrap();
    assert_eq!(code_of(&bad.create(&files_of(&[("a.md", "hi")]), "", false).unwrap_err()), "unauthorized");
    assert_eq!(code_of(&authed(&s).get("0123456789abcdef").unwrap_err()), "not_found");
    assert_eq!(code_of(&authed(&s).get("../etc").unwrap_err()), "bad_id");
}

#[test]
fn client_a_rate_limit_says_so_and_when_it_ends() {
    let s = Server::with(1_000_000, true);
    let e = anon(&s).get("0123456789abcdef").unwrap_err();
    assert_eq!(code_of(&e), "rate_limited");
    assert!(e.message.contains("resets 2033"), "{e}");
    assert!(e.message.contains("GITHUB_TOKEN"), "{e}");
}

#[test]
fn client_the_token_never_goes_to_a_plain_http_host_nor_to_the_raw_file_host() {
    // An http API that is not loopback: a write refuses before any request,
    // and the client says it would not sign anything for that host.
    let plain = GistApi::with_token(Some("http://gists.example.com"), Some(TOKEN)).unwrap();
    assert!(!plain.can_write());
    let e = plain.create(&files_of(&[("a.md", "x")]), "", false).unwrap_err();
    assert_eq!(code_of(&e), "insecure_api");
    // Loopback is the exception that lets the tests run.
    let s = Server::start();
    assert!(authed(&s).can_write());
    assert!(GistApi::new(Some("ftp://example.com")).is_err());

    // A truncated file is fetched from its raw URL, with no credentials at all.
    let s = Server::with(10, false);
    let id = s.seed(&[("big.md", &"x".repeat(50))]);
    let api = authed(&s);
    let g = api.get(&id).unwrap();
    assert!(g.files["big.md"].truncated);
    assert_eq!(api.content(&g.files["big.md"]).unwrap().len(), 50);
    let raw: Vec<Req> = s.requests().into_iter().filter(|r| r.path.starts_with("/raw/")).collect();
    assert_eq!(raw.len(), 1);
    assert_eq!(raw[0].auth, None);
}

// ------------------------------------------------------------------ export

#[test]
fn export_a_folder_becomes_a_secret_gist_with_flat_names_and_says_what_it_left_out() {
    let s = Server::start();
    let (dir, v) = copy_of_vault();
    // The fixture's "diagram.png" is a text placeholder; this one is a real PNG header.
    write(&dir, "content/Assets/real.png", &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]);

    let r = export(&v, &authed(&s), ExportArgs { folder: "", ..Default::default() }).unwrap();
    assert!(r.created);
    assert!(!r.public);
    assert_eq!(
        r.skipped.iter().map(|x| (x.path.as_str(), x.reason)).collect::<Vec<_>>(),
        vec![("Assets/real.png", "not_text")]
    );
    assert_eq!(
        sorted(r.names.clone()),
        ["Assets%2Fdiagram.png", "Notes%2FColumns.md", "Notes%2FHexes.md", "Notes%2FStart Here.md"]
    );
    let id = r.id.unwrap();
    let files = s.files(&id);
    assert_eq!(
        files["Notes%2FHexes.md"],
        std::fs::read_to_string(fixture().join("content/Notes/Hexes.md")).unwrap()
    );
}

#[test]
fn export_a_subfolder_is_named_relative_to_itself() {
    let s = Server::start();
    let (_d, v) = copy_of_vault();
    let r = export(
        &v,
        &authed(&s),
        ExportArgs { folder: "Notes/", public: true, description: Some("d"), ..Default::default() },
    )
    .unwrap();
    assert_eq!(sorted(r.names.clone()), ["Columns.md", "Hexes.md", "Start Here.md"]);
    assert!(r.public);
    assert_eq!(s.description(r.id.as_ref().unwrap()), "d");
}

#[test]
fn export_a_principal_sends_only_what_it_may_read_and_the_rest_is_counted_not_named() {
    let s = Server::start();
    let (_d, mut v) = copy_of_vault();
    v.reindex(false).unwrap(); // a principal's view needs inline ACLs
    let r = export(
        &v,
        &authed(&s),
        ExportArgs { folder: "Notes/", principal: Some("u:reader"), ..Default::default() },
    )
    .unwrap();
    assert_eq!(sorted(r.names.clone()), ["Hexes.md", "Start Here.md"]);
    assert_eq!(r.withheld, 1);
    assert!(!format!("{r:?}").contains("Columns"), "a withheld path must not be named");
    let owner = export(
        &v,
        &authed(&s),
        ExportArgs { folder: "Notes/", principal: Some("u:carter"), ..Default::default() },
    )
    .unwrap();
    assert_eq!(owner.names.len(), 3);
}

#[test]
fn export_dry_run_works_out_the_files_and_makes_no_request() {
    let s = Server::start();
    let (_d, v) = copy_of_vault();
    let r = export(&v, &authed(&s), ExportArgs { folder: "Notes/", dry_run: true, ..Default::default() }).unwrap();
    assert!(r.dry_run);
    assert_eq!(r.count, 3);
    assert_eq!(s.requests().len(), 0);
    assert_eq!(s.gist_count(), 0);
}

#[test]
fn export_empty_and_blank_files_are_left_out_named_and_an_all_empty_folder_is_an_error() {
    let s = Server::start();
    let (dir, v) = copy_of_vault();
    write(&dir, "content/Odd/zero.md", b"");
    write(&dir, "content/Odd/blank.md", b" \n\n");
    let e = export(&v, &authed(&s), ExportArgs { folder: "Odd/", ..Default::default() }).unwrap_err();
    assert!(e.contains("nothing to export"), "{e}");
    write(&dir, "content/Odd/real.md", b"# real\n");
    let r = export(&v, &authed(&s), ExportArgs { folder: "Odd/", ..Default::default() }).unwrap();
    assert_eq!(r.names, ["real.md"]);
    assert_eq!(
        r.skipped.iter().map(|x| (x.path.as_str(), x.reason)).collect::<Vec<_>>(),
        vec![("Odd/blank.md", "empty"), ("Odd/zero.md", "empty")]
    );
    assert_eq!(s.requests().len(), 1, "one create; the empty files never went out");
}

#[test]
fn export_a_file_name_the_protocol_forbids_is_named_as_left_out_not_lost_quietly() {
    let s = Server::start();
    let (dir, v) = copy_of_vault();
    // "Café" spelled with a combining accent: §1.1 requires NFC, so it is no object of the vault.
    write(&dir, "content/Notes/Cafe\u{301}.md", b"# decomposed\n");
    let r = export(&v, &authed(&s), ExportArgs { folder: "Notes/", ..Default::default() }).unwrap();
    assert_eq!(r.skipped.iter().map(|x| x.reason).collect::<Vec<_>>(), ["invalid_key"]);
    assert_eq!(r.count, 3);
    // Listed even for a principal: it is in no index, so there is no ACL to ask.
    let picked = collect(&v, "Notes/", false, Some("u:reader")).unwrap();
    assert_eq!(picked.skipped.iter().map(|x| x.reason).collect::<Vec<_>>(), ["invalid_key"]);
}

#[test]
fn export_more_files_than_a_gist_shows_is_refused_before_anything_is_sent() {
    let s = Server::start();
    let (dir, v) = copy_of_vault();
    for i in 0..301 {
        write(&dir, &format!("content/Many/n{i}.md"), format!("n{i}\n").as_bytes());
    }
    let e = export(&v, &authed(&s), ExportArgs { folder: "Many/", ..Default::default() }).unwrap_err();
    assert!(e.contains("more than a gist shows"), "{e}");
    assert_eq!(s.requests().len(), 0);
}

#[test]
fn export_public_goes_with_a_new_gist_only_and_prune_with_update_only() {
    let s = Server::start();
    let (_d, v) = copy_of_vault();
    let api = authed(&s);
    let e = export(&v, &api, ExportArgs { folder: "Notes/", update: Some("abcde"), public: true, ..Default::default() })
        .unwrap_err();
    assert!(e.contains("cannot change sides"), "{e}");
    let e = export(&v, &api, ExportArgs { folder: "Notes/", prune: true, ..Default::default() }).unwrap_err();
    assert!(e.contains("--prune is for --update"), "{e}");
    let e = export(&v, &api, ExportArgs { whole: true, principal: Some("u:reader"), ..Default::default() }).unwrap_err();
    assert!(e.contains("operator"), "{e}");
    assert_eq!(s.requests().len(), 0);
}

#[test]
fn export_update_writes_what_changed_leaves_the_gists_other_files_unless_pruned() {
    let s = Server::start();
    let (dir, v) = copy_of_vault();
    let api = authed(&s);
    let first = export(&v, &api, ExportArgs { folder: "Notes/", ..Default::default() }).unwrap();
    let id = first.id.unwrap();
    s.put_file(&id, "mine.txt", "something I added on the website");

    // Nothing changed: no PATCH at all.
    let same = export(&v, &api, ExportArgs { folder: "Notes/", update: Some(&id), ..Default::default() }).unwrap();
    assert!(!same.updated);
    assert_eq!(same.unchanged, 3);
    assert_eq!(same.left, ["mine.txt"]);
    assert_eq!(s.count("PATCH"), 0);

    // One note edited, one added: those two are written, the rest untouched.
    write(&dir, "content/Notes/Hexes.md", b"# changed\n");
    write(&dir, "content/Notes/New.md", b"# new\n");
    let r = export(&v, &api, ExportArgs { folder: "Notes/", update: Some(&id), ..Default::default() }).unwrap();
    assert_eq!((r.written, r.unchanged, r.removed), (2, 2, 0));
    assert!(s.files(&id).contains_key("mine.txt"), "a file basalt did not write is kept");
    assert_eq!(s.files(&id)["Hexes.md"], "# changed\n");

    // --prune takes out what the folder no longer has, and only that.
    std::fs::remove_file(dir.0.join("content/Notes/New.md")).unwrap();
    let p = export(&v, &api, ExportArgs { folder: "Notes/", update: Some(&id), prune: true, ..Default::default() })
        .unwrap();
    assert_eq!(p.removed, 2); // New.md and mine.txt
    assert_eq!(s.files(&id).keys().cloned().collect::<Vec<_>>(), ["Columns.md", "Hexes.md", "Start Here.md"]);
}

// ------------------------------------------------------------------ import

fn import(
    v: &mut Vault,
    api: &GistApi,
    id: &str,
    to: &str,
    principal: Option<&str>,
) -> basalt::gist::ImportReport {
    import_from_gist(v, api, id, to, principal, None, |_| {}).unwrap()
}

#[test]
fn import_every_file_lands_as_a_new_object_with_an_id_and_a_second_import_refuses_not_replaces() {
    let s = Server::start();
    let (_d, mut v) = copy_of_vault();
    let id = s.seed(&[
        ("Intro.md", "# Intro\n\nSee [[Hexes]].\n"),
        ("Deep%2FNested%2Fnote.md", "nested\n"),
        ("data.json", "{\"a\": 1}\n"),
    ]);

    let r = import(&mut v, &anon(&s), &id, "Gists/x/", None);
    assert!(r.refused.is_empty(), "{:?}", r.refused);
    assert_eq!(
        sorted(r.stored.iter().map(|o| o.path.clone()).collect()),
        ["Gists/x/Deep/Nested/note.md", "Gists/x/Intro.md", "Gists/x/data.json"]
    );
    for o in &r.stored {
        assert_eq!(o.id.len(), 26, "{}", o.id);
    }
    let intro = String::from_utf8(v.transport.get("content/Gists/x/Intro.md").unwrap().unwrap()).unwrap();
    assert!(intro.starts_with("---\nbasalt:\n  id: "), "{intro}");
    assert!(intro.ends_with("# Intro\n\nSee [[Hexes]].\n"), "{intro}");
    v.reindex(false).unwrap();
    let errors = v
        .indexes
        .as_ref()
        .unwrap()
        .issues
        .iter()
        .filter(|i| i.severity == basalt::frontmatter::Severity::Error)
        .count();
    assert_eq!(errors, 0);

    let again = import(&mut v, &anon(&s), &id, "Gists/x/", None);
    assert_eq!(again.stored.len(), 0);
    assert_eq!(again.refused.len(), 3);
    assert!(again.refused[0].1.contains("already exists"), "{:?}", again.refused[0]);
    // Reading a gist took no token, and sent none.
    assert!(s.requests().iter().all(|q| q.auth.is_none()));
}

#[test]
fn import_one_bad_name_is_refused_and_the_others_still_go() {
    let s = Server::start();
    let (_d, mut v) = copy_of_vault();
    let id = s.seed(&[("ok.md", "fine\n"), ("a%2F..%2Fb.md", "escapes\n"), ("Notes%2FHexes.md", "taken?\n")]);
    // Into the vault root, so "Notes/Hexes.md" is a path that is already taken.
    let r = import(&mut v, &anon(&s), &id, "", None);
    assert_eq!(r.stored.iter().map(|o| o.path.as_str()).collect::<Vec<_>>(), ["ok.md"]);
    assert_eq!(r.refused.len(), 2);
    assert!(r.refused.iter().any(|(_, e)| e.contains("not a valid path")), "{:?}", r.refused);
    assert!(r.refused.iter().any(|(_, e)| e.contains("already exists")), "{:?}", r.refused);
    // The note that was taken is untouched, and nothing went outside the vault.
    let hexes = String::from_utf8(v.transport.get("content/Notes/Hexes.md").unwrap().unwrap()).unwrap();
    assert!(hexes.contains("Hexagons"));
}

#[test]
fn import_a_principal_needs_create_child_on_the_folder() {
    let s = Server::start();
    let (_d, mut v) = copy_of_vault();
    v.reindex(false).unwrap();
    let id = s.seed(&[("a.md", "x\n")]);
    let r = import(&mut v, &anon(&s), &id, "Notes/", Some("u:reader"));
    assert_eq!(r.stored.len(), 0);
    assert_eq!(r.refused.len(), 1);
    assert!(v.transport.get("content/Notes/a.md").unwrap().is_none());
}

#[test]
fn import_a_file_the_listing_truncated_is_fetched_whole() {
    let s = Server::with(20, false);
    let (_d, mut v) = copy_of_vault();
    let body = format!("# Long\n\n{}\n", "word ".repeat(40));
    let id = s.seed(&[("long.md", &body)]);
    let r = import(&mut v, &anon(&s), &id, "In/", None);
    assert_eq!(r.stored.len(), 1);
    let got = String::from_utf8(v.transport.get("content/In/long.md").unwrap().unwrap()).unwrap();
    assert!(got.ends_with(&body));
}

fn strip_frontmatter(x: &str) -> &str {
    match x.strip_prefix("---\n").and_then(|r| r.find("\n---\n").map(|i| &r[i + 5..])) {
        Some(body) => body,
        None => x,
    }
}

fn id_of(x: &str) -> Option<String> {
    let i = x.find("id: ")? + 4;
    Some(x[i..].chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect())
}

#[test]
fn round_trip_export_a_folder_import_it_elsewhere_the_text_survives() {
    let s = Server::start();
    let (_a, a) = copy_of_vault();
    let (_b, mut b) = copy_of_vault();
    let out = export(&a, &authed(&s), ExportArgs { folder: "Notes/", ..Default::default() }).unwrap();
    let back = import(&mut b, &anon(&s), out.id.as_ref().unwrap(), "Copy/", None);
    assert!(back.refused.is_empty(), "{:?}", back.refused);
    assert_eq!(back.stored.len(), 3);
    for name in ["Columns", "Hexes", "Start Here"] {
        let orig = String::from_utf8(a.transport.get(&format!("content/Notes/{name}.md")).unwrap().unwrap()).unwrap();
        let copy = String::from_utf8(b.transport.get(&format!("content/Copy/{name}.md")).unwrap().unwrap()).unwrap();
        assert_eq!(strip_frontmatter(&copy), strip_frontmatter(&orig), "{name}");
        // A fresh identity, not the source vault's.
        assert_ne!(id_of(&copy), id_of(&orig), "{name}");
    }
}

// ------------------------------------------------------------- gist store

fn store_note(v: &mut Vault, path: &str, text: &str) -> Result<basalt::store::Stored, basalt::store::StoreError> {
    store_object(
        v,
        &StoreRequest {
            principal: None,
            path,
            bytes: text.as_bytes(),
            title: None,
            alt: None,
            provenance: None,
            reindex: true,
            max_bytes: None,
        },
    )
}

#[test]
fn store_a_whole_vault_in_a_gist_opens_reads_and_a_batch_of_writes_is_one_revision() {
    let s = Server::start();
    let (_d, v) = copy_of_vault();
    let out = export(&v, &authed(&s), ExportArgs { whole: true, ..Default::default() }).unwrap();
    assert!(out.names.contains(&"basalt.yaml".to_string()));
    assert!(out.names.contains(&"content%2FNotes%2FHexes.md".to_string()));
    let id = out.id.unwrap();

    let mut g = Vault::open(Box::new(GistTransport::new(&id, authed(&s)).unwrap())).unwrap();
    g.reindex(false).unwrap();
    let notes = g.indexes.as_ref().unwrap().node_data.iter().filter(|n| n.path.starts_with("Notes/")).count();
    assert_eq!(notes, 3);

    assert_eq!(s.count("PATCH"), 0);
    let stored = store_note(&mut g, "Notes/Added.md", "# Added\n").unwrap();
    assert_eq!(stored.path, "Notes/Added.md");
    assert_eq!(s.count("PATCH"), 1, "the note and the refreshed indexes went out as one PATCH");
    let files = s.files(&id);
    assert!(files.contains_key("content%2FNotes%2FAdded.md"));
    assert!(files.contains_key("index%2Fnodes.json"));

    // A second process sees it.
    let other = Vault::open(Box::new(
        GistTransport::new(&id, anon(&s)).unwrap().with_ttl(Duration::ZERO),
    ))
    .unwrap();
    assert!(other.transport.get("content/Notes/Added.md").unwrap().is_some());
    let e = store_note(&mut g, "Notes/Added.md", "again").unwrap_err();
    assert!(e.to_string().contains("never overwrite"), "{e}");
}

#[test]
fn store_what_a_gist_cannot_hold_is_refused_by_name_not_mangled() {
    let s = Server::start();
    let id = s.seed(&[("basalt.yaml", "basalt: 1\n")]);
    let tr = GistTransport::new(&id, authed(&s)).unwrap();
    tr.ready().unwrap();
    let put = |key: &str, bytes: &[u8]| tr.put(key, bytes, &PutMeta::default()).unwrap_err().to_string();
    assert!(put("content/Assets/a.png", &[0x89, 0x50, 0, 1]).contains("not UTF-8 text"));
    assert!(put("content/Notes/empty.md", b"").contains("empty"));
    assert!(put(&format!("content/{}.md", "x".repeat(300)), b"x").contains("longer than"));
    assert_eq!(s.count("PATCH"), 0);
}

fn create_only() -> PutMeta {
    PutMeta { content_type: None, if_match: Some(None) }
}

#[test]
fn store_list_stat_delete_and_a_conditional_put_behave_like_the_others() {
    let s = Server::start();
    let id = s.seed(&[
        ("basalt.yaml", "basalt: 1\n"),
        ("content%2FA%2Fb.md", "hello\n"),
        ("content%2FA%2Fc.md", "c\n"),
    ]);
    let tr = GistTransport::new(&id, authed(&s)).unwrap().with_ttl(Duration::ZERO);
    tr.ready().unwrap();

    assert_eq!(sorted(tr.list_all("content/A/").unwrap()), ["content/A/b.md", "content/A/c.md"]);
    let top = tr.list("", &ListOpts { delimiter: Some('/'), cursor: None }).unwrap();
    assert_eq!(top.keys, ["basalt.yaml"]);
    assert_eq!(top.prefixes, ["content/"]);
    let st = tr.stat("content/A/b.md").unwrap().unwrap();
    assert_eq!(st.size, 6);
    let etag = st.etag.clone().unwrap();
    assert!(etag.starts_with('"') && etag.len() == 34, "{etag}");
    assert!(tr.get("content/A/zzz.md").unwrap().is_none());
    assert!(tr.stat("content/A/zzz.md").unwrap().is_none());

    // Create-only: refused when the key exists, allowed when it does not.
    assert!(matches!(
        tr.put("content/A/b.md", b"x", &create_only()),
        Err(TransportError::PreconditionFailed(_))
    ));
    tr.put("content/A/new.md", b"n\n", &create_only()).unwrap();
    assert_eq!(s.files(&id)["content%2FA%2Fnew.md"], "n\n");
    // Stale etag.
    let stale = PutMeta { content_type: None, if_match: Some(Some("\"stale\"".into())) };
    assert!(matches!(tr.put("content/A/b.md", b"x", &stale), Err(TransportError::PreconditionFailed(_))));
    // The right etag replaces.
    let right = PutMeta { content_type: None, if_match: Some(Some(etag)) };
    tr.put("content/A/b.md", b"x\n", &right).unwrap();
    assert_eq!(s.files(&id)["content%2FA%2Fb.md"], "x\n");

    tr.delete("content/A/c.md").unwrap();
    let patches = s.count("PATCH");
    tr.delete("content/A/never-existed.md").unwrap(); // idempotent, and sends nothing for it
    assert_eq!(s.count("PATCH"), patches);
    assert!(!s.files(&id).contains_key("content%2FA%2Fc.md"));
    assert!(tr.capabilities().is_empty());
}

#[test]
fn store_a_gist_too_big_for_the_api_to_list_is_refused_up_front() {
    let s = Server::start();
    let id = s.seed_many(301);
    let e = GistTransport::new(&id, authed(&s)).unwrap().ready().unwrap_err();
    assert!(e.to_string().contains("clone it with git"), "{e}");
}

// --------------------------------------------------------------------- CLI

fn cli(s: &Server, args: &[&str], token: Option<&str>) -> (Option<i32>, String, String) {
    // `gh` is left off the PATH so a developer's own login cannot be found,
    // and the rest of the environment (proxies, GITHUB_API_URL) is shut out.
    let out = Command::new(env!("CARGO_BIN_EXE_basalt"))
        .args(args)
        .args(["--api-url", &s.url])
        .env_clear()
        .env("PATH", "/nonexistent")
        .env("HOME", std::env::temp_dir())
        .env("NO_COLOR", "1")
        .env("GITHUB_TOKEN", token.unwrap_or(""))
        .env("GH_TOKEN", "")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn p(d: &Scratch) -> &str {
    d.0.to_str().unwrap()
}

#[test]
fn cli_export_dry_run_export_then_import_into_a_vault_end_to_end() {
    let s = Server::start();
    let (dir, _v) = copy_of_vault();
    let (other, _w) = copy_of_vault();
    write(&dir, "content/Assets/real.png", &[0x89, 0x50, 0, 1]);

    let (code, out, err) = cli(&s, &["gist", "export", "Notes/", "--vault", p(&dir), "--dry-run"], Some(TOKEN));
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("would send 3 file(s)") && out.contains("secret gist"), "{out}");
    assert!(out.contains("Hexes.md"));
    assert_eq!(s.requests().len(), 0);

    // A boolean flag does not swallow the folder that follows it.
    let (code, out, err) = cli(&s, &["gist", "export", "--dry-run", "Notes/", "--vault", p(&dir)], Some(TOKEN));
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("would send 3 file(s)"), "{out}");

    let (code, out, err) = cli(&s, &["gist", "export", "", "--vault", p(&dir)], Some(TOKEN));
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("created secret gist https://gist.github.com/test/"), "{out}");
    assert!(out.contains("Secret means unlisted, not private"), "{out}");
    assert!(out.contains("Assets/real.png") && out.contains("not text a gist can hold"), "{out}");
    let id = s.only_gist();

    let url = format!("https://gist.github.com/someone/{id}");
    let (code, out, err) = cli(&s, &["gist", "import", &url, "--vault", p(&other), "--to", "From/"], None);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("stored  From/Notes/Hexes.md"), "{out}");
    assert!(out.contains("4 stored, 0 refused"), "{out}");
    let got = std::fs::read_to_string(other.0.join("content/From/Notes/Hexes.md")).unwrap();
    assert!(got.contains("Hexagons"));

    let (code, _out, err) = cli(&s, &["gist", "import", &id, "--vault", p(&other), "--to", "From/"], None);
    assert_eq!(code, Some(1));
    assert!(err.contains("already exists"), "{err}");
}

#[test]
fn cli_no_token_means_no_export_and_it_says_how_to_fix_that() {
    let s = Server::start();
    let (dir, _v) = copy_of_vault();
    let (code, _out, err) = cli(&s, &["gist", "export", "Notes/", "--vault", p(&dir)], None);
    assert_ne!(code, Some(0));
    assert!(err.contains("GITHUB_TOKEN"), "{err}");
    assert_eq!(s.requests().len(), 0);
}

#[test]
fn cli_gist_opens_a_vault_from_a_gist_and_a_token_is_never_taken_as_a_flag() {
    let s = Server::start();
    let (dir, _v) = copy_of_vault();
    let (code, _out, err) = cli(&s, &["gist", "export", "--whole", "--vault", p(&dir)], Some(TOKEN));
    assert_eq!(code, Some(0), "{err}");
    let id = s.only_gist();

    let (code, out, err) = cli(&s, &["tree", "--gist", &id, "--principal", "u:carter"], None);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("Hexes.md"), "{out}");

    let (_code, _out, err) = cli(&s, &["index", "--gist", &id, "--vault", p(&dir)], None);
    assert!(err.contains("pick one store"), "{err}");

    // There is no --token flag: it would end up in shell history and `ps`.
    let posts = s.count("POST");
    let (code, _out, err) = cli(&s, &["gist", "export", "Notes/", "--vault", p(&dir), "--token", "x"], None);
    assert_ne!(code, Some(0));
    assert!(err.contains("no --token flag"), "{err}");
    assert_eq!(s.count("POST"), posts);
}

#[test]
fn collect_lists_the_same_files_every_time_in_name_order() {
    let (_d, v) = copy_of_vault();
    let a = collect(&v, "", false, None).unwrap();
    let b = collect(&v, "", false, None).unwrap();
    let names: Vec<&str> = a.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, b.files.iter().map(|f| f.name.as_str()).collect::<Vec<_>>());
    let mut sorted_names = names.clone();
    sorted_names.sort();
    assert_eq!(names, sorted_names);
}
