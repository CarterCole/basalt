//! The interop surfaces, PROTOCOL §17 and `protocol/INTEROP.md`.
//!
//! Two claims are under test. The first is that this implementation serves
//! `P-REST` and `P-MCP` as the annex specifies them. The second, and the one
//! worth the file, is INTEROP §9: the surfaces answer the *same* questions the
//! *same* way for the same principal, so adding a protocol adds translation
//! and never policy.
//!
//! Expectations come out of `conformance/cases/interop/`, never from here
//! (§14.2): the operation spellings and the fault table are pinned by the
//! corpus, so renaming one in Rust fails against the committed YAML.

mod support;

use basalt::canonical::{parse_json, Json};
use basalt::gatekeeper::{Gatekeeper, Request, Response};
use basalt::serve::ops::OPERATIONS;
use basalt::serve::router::SurfaceKind;
use basalt::serve::surface::Fault;
use basalt::transport::FsTransport;
use basalt::vault::Vault;
use std::collections::{BTreeMap, BTreeSet};
use support::{list, load, s, Report};

const VAULT_ID: &str = "01JBQ7X8Z4N3VYK9M2T5HRWC6P";

fn vault() -> Vault {
    let dir = support::conformance_dir().join("vaults/minimal/vault");
    let mut v = Vault::open(Box::new(FsTransport::new(&dir))).expect("vault opens");
    v.reindex(false).expect("reindex");
    v
}

/// These suites exist to exercise the interop surfaces, so they mount them
/// explicitly. The production default is the §12 read API alone (§14.1);
/// relying on a permissive default here would have hidden that it was
/// permissive, which is exactly how the old fail-open default survived.
fn gatekeeper_for(principal: &str) -> Gatekeeper {
    Gatekeeper::new(vault())
        .with_surfaces(SurfaceKind::ALL.into_iter().collect())
        .with_fixed_principal(principal)
}

fn request(method: &str, path: &str) -> Request {
    let (p, q) = match path.split_once('?') {
        Some((p, q)) => (
            p.to_string(),
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ),
        None => (path.to_string(), BTreeMap::new()),
    };
    Request {
        method: method.into(),
        path: p,
        query: q,
        headers: BTreeMap::new(),
    }
}

fn get(gk: &Gatekeeper, path: &str) -> Response {
    gk.handle(&request("GET", path))
}

fn body_of(r: &Response) -> Json {
    parse_json(&String::from_utf8_lossy(&r.body)).unwrap_or(Json::Null)
}

fn header(r: &Response, name: &str) -> Option<String> {
    r.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// One JSON-RPC call against `/mcp`, as a client would make it.
fn rpc(gk: &Gatekeeper, method: &str, params: Json) -> Json {
    let msg = Json::obj()
        .set("jsonrpc", Json::str("2.0"))
        .set("id", Json::Int(1))
        .set("method", Json::str(method))
        .set("params", params)
        .build();
    let r = gk.handle_with_body(&request("POST", "/mcp"), msg.to_compact_string().as_bytes());
    assert_eq!(r.status, 200, "/mcp answers 200 and carries the error inside");
    body_of(&r)
}

fn tool_call(gk: &Gatekeeper, tool: &str, args: Json) -> Json {
    rpc(
        gk,
        "tools/call",
        Json::obj()
            .set("name", Json::str(tool))
            .set("arguments", args)
            .build(),
    )
}

fn strings(v: &Json) -> Vec<String> {
    v.as_array()
        .unwrap_or(&[])
        .iter()
        .filter_map(|x| x.as_str().map(String::from))
        .collect()
}

// ------------------------------------------------- the corpus pins the table

/// INTEROP §1.2 and §1.3: the operation spellings and the fault table live in
/// `conformance/cases/interop/surfaces.yaml`, and this implementation is held
/// to them rather than the other way round.
#[test]
fn corpus_pins_the_operation_table_and_the_faults() {
    let doc = load("cases/interop/surfaces.yaml");
    let mut r = Report::default();

    let declared = doc
        .get("operations")
        .and_then(|o| o.as_sequence())
        .expect("surfaces.yaml declares operations");

    r.check(
        "operations",
        "count",
        OPERATIONS.len(),
        declared.len(),
    );
    for spec in declared {
        let name = s(spec, "name").expect("each operation is named");
        let Some(op) = OPERATIONS.iter().find(|o| o.name == name) else {
            r.check(&name, "implemented", false, true);
            continue;
        };
        r.check(&name, "JSON-RPC method", format!("basalt.{}", op.name), s(spec, "rpc").unwrap_or_default());
        r.check(&name, "MCP tool", format!("basalt_{}", op.name), s(spec, "tool").unwrap_or_default());
        r.check(&name, "proto method", op.proto.to_string(), s(spec, "proto").unwrap_or_default());
        r.check(
            &name,
            "arguments",
            op.args.iter().map(|a| a.name.to_string()).collect::<Vec<_>>(),
            list(spec, "args"),
        );
        r.check(
            &name,
            "required arguments",
            op.args
                .iter()
                .filter(|a| a.required)
                .map(|a| a.name.to_string())
                .collect::<Vec<_>>(),
            list(spec, "required"),
        );
    }

    let faults = doc
        .get("faults")
        .and_then(|f| f.as_sequence())
        .expect("surfaces.yaml declares the fault table");
    r.check(
        "faults",
        "count",
        Fault::all().len(),
        faults.len(),
    );
    for row in faults {
        let name = s(row, "fault").expect("each row names a fault");
        let Some(f) = Fault::all().into_iter().find(|f| f.code() == name) else {
            r.check(&name, "implemented", false, true);
            continue;
        };
        r.check(&name, "HTTP status", f.status().to_string(), s(row, "http").unwrap_or_default());
        r.check(&name, "Connect code", f.connect().to_string(), s(row, "connect").unwrap_or_default());
        r.check(&name, "JSON-RPC code", f.rpc().to_string(), s(row, "jsonrpc").unwrap_or_default());
    }

    // The profiles this implementation claims are the ones the corpus knows.
    let profiles: Vec<String> = support::cases(&doc)
        .iter()
        .filter_map(|c| s(c, "id"))
        .collect();
    for kind in SurfaceKind::ALL {
        r.check(
            kind.as_str(),
            "profile is described by the corpus",
            profiles.contains(&kind.profile().to_string()),
            true,
        );
    }
    r.finish("interop/surfaces");
}

// -------------------------------------------------------------- P-REST (§2)

/// INTEROP §2: every route the server serves is described, with both denials.
#[test]
fn openapi_describes_every_route() {
    let gk = gatekeeper_for("u:reader");
    let doc = body_of(&get(&gk, "/api/v1/openapi.json"));
    assert_eq!(doc.get("openapi").and_then(|v| v.as_str()), Some("3.1.0"));

    let paths = doc.get("paths").and_then(|p| p.as_object()).expect("paths");
    let corpus = load("cases/interop/surfaces.yaml");
    let rest = support::cases(&corpus)
        .into_iter()
        .find(|c| s(c, "id").as_deref() == Some("P-REST"))
        .expect("the corpus describes P-REST");

    let mut r = Report::default();
    for route in rest
        .get("routes")
        .and_then(|x| x.as_sequence())
        .expect("P-REST lists routes")
    {
        let path = s(route, "path").expect("each route has a path");
        let Some(entry) = paths.get(&path) else {
            r.check(&path, "documented", false, true);
            continue;
        };
        let responses = entry.get("get").and_then(|g| g.get("responses"));
        // §12.3's two denials are a contract, not an implementation detail.
        for code in ["200", "403", "404"] {
            r.check(
                &path,
                &format!("documents {code}"),
                responses.and_then(|x| x.get(code)).is_some(),
                true,
            );
        }
    }
    // A $ref that does not resolve is the failure that breaks codegen
    // silently, so the document is walked rather than eyeballed.
    let schemas = doc
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(|s| s.as_object())
        .expect("components.schemas");
    let mut refs: Vec<String> = Vec::new();
    collect_refs(&doc, &mut refs);
    for reference in &refs {
        let name = reference.trim_start_matches("#/components/schemas/");
        r.check(name, "$ref resolves", schemas.contains_key(name), true);
    }
    assert!(refs.len() > 10, "the document should be built from components");
    r.finish("interop/openapi");
}

fn collect_refs(value: &Json, out: &mut Vec<String>) {
    match value {
        Json::Object(map) => {
            for (k, v) in map {
                if k == "$ref" {
                    if let Some(r) = v.as_str() {
                        out.push(r.to_string());
                    }
                } else {
                    collect_refs(v, out);
                }
            }
        }
        Json::Array(items) => items.iter().for_each(|i| collect_refs(i, out)),
        _ => {}
    }
}

/// INTEROP §2: denials are RFC 9457 problem documents, and the legacy `error`
/// member stays for a client written against the pre-annex surface.
#[test]
fn denials_are_problem_documents() {
    let gk = gatekeeper_for("u:reader");
    let missing = get(&gk, "/api/v1/node/Notes/Nope.md");
    assert_eq!(missing.status, 404);
    assert_eq!(
        header(&missing, "content-type").as_deref(),
        Some("application/problem+json")
    );
    let body = body_of(&missing);
    assert_eq!(
        body.get("type").and_then(|t| t.as_str()),
        Some("urn:basalt:problem:not_found")
    );
    assert_eq!(body.get("error").and_then(|e| e.as_str()), Some("not_found"));

    let forbidden = get(&gk, "/api/v1/node/Notes/Columns.md");
    assert_eq!(forbidden.status, 403);
    assert_eq!(
        body_of(&forbidden).get("error").and_then(|e| e.as_str()),
        Some("forbidden")
    );
}

/// INTEROP §1.5.2: a conditional GET works, and the validator depends on the
/// principal's visibility — a shared cache keyed on the URL alone would hand
/// the reader the owner's body.
#[test]
fn conditional_get_is_per_principal() {
    let reader = gatekeeper_for("u:reader");
    let owner = gatekeeper_for("u:carter");

    let first = get(&reader, "/api/v1/nodes");
    let etag = header(&first, "etag").expect("a JSON route carries an etag");
    assert!(etag.starts_with("W/\""), "{etag}");

    let mut again = request("GET", "/api/v1/nodes");
    again
        .headers
        .insert("if-none-match".into(), etag.clone());
    let not_modified = reader.handle(&again);
    assert_eq!(not_modified.status, 304);
    assert!(not_modified.body.is_empty());

    let owners = get(&owner, "/api/v1/nodes");
    assert_ne!(
        header(&owners, "etag"),
        Some(etag.clone()),
        "two principals with different visibility shared a validator"
    );
    let mut crossed = request("GET", "/api/v1/nodes");
    crossed.headers.insert("if-none-match".into(), etag);
    assert_eq!(owner.handle(&crossed).status, 200);
    assert_eq!(
        header(&first, "cache-control").as_deref(),
        Some("private, no-store")
    );
}

// ------------------------------------------------------------- P-MCP (§4.2)

#[test]
fn mcp_handshake_tools_and_resources() {
    let gk = gatekeeper_for("u:reader");

    let init = rpc(
        &gk,
        "initialize",
        Json::obj()
            .set("protocolVersion", Json::str("2025-03-26"))
            .build(),
    );
    let result = init.get("result").expect("initialize answers");
    // §4.2.1: a supported version is echoed; an unknown one gets ours.
    assert_eq!(
        result.get("protocolVersion").and_then(|v| v.as_str()),
        Some("2025-03-26")
    );
    let future = rpc(
        &gk,
        "initialize",
        Json::obj()
            .set("protocolVersion", Json::str("2099-01-01"))
            .build(),
    );
    assert_eq!(
        future
            .get("result")
            .and_then(|r| r.get("protocolVersion"))
            .and_then(|v| v.as_str()),
        Some(basalt::serve::mcp::MCP_LATEST)
    );

    let tools = rpc(&gk, "tools/list", Json::obj().build());
    let listed: Vec<String> = tools
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .expect("tools/list answers")
        .iter()
        .map(|t| {
            // Every tool carries a schema and a description, or a model
            // cannot tell what it is being offered.
            assert!(t.get("description").and_then(|d| d.as_str()).is_some());
            assert_eq!(
                t.get("inputSchema")
                    .and_then(|s| s.get("type"))
                    .and_then(|v| v.as_str()),
                Some("object")
            );
            t.get("name").and_then(|n| n.as_str()).unwrap().to_string()
        })
        .collect();
    assert_eq!(
        listed,
        OPERATIONS
            .iter()
            .map(|o| format!("basalt_{}", o.name))
            .collect::<Vec<_>>()
    );

    let called = tool_call(
        &gk,
        "basalt_node",
        Json::obj().set("path", Json::str("Notes/Hexes.md")).build(),
    );
    let content = called
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
        .expect("a tool result carries content");
    let payload = parse_json(content[0].get("text").and_then(|t| t.as_str()).unwrap())
        .expect("the content is the operation's JSON");
    assert_eq!(
        payload
            .get("node")
            .and_then(|n| n.get("title"))
            .and_then(|t| t.as_str()),
        Some("Hexagons")
    );

    let resources = rpc(&gk, "resources/list", Json::obj().build());
    let uris = strings(
        &resources
            .get("result")
            .and_then(|r| r.get("resources"))
            .map(|rs| {
                Json::Array(
                    rs.as_array()
                        .unwrap_or(&[])
                        .iter()
                        .map(|x| x.get("uri").cloned().unwrap_or(Json::Null))
                        .collect(),
                )
            })
            .unwrap_or(Json::Null),
    );
    assert!(uris
        .iter()
        .all(|u| u.starts_with(&format!("basalt://{VAULT_ID}/"))));
    assert!(
        !uris.iter().any(|u| u.contains("Columns")),
        "an unreadable node was advertised: {uris:?}"
    );

    let read = rpc(
        &gk,
        "resources/read",
        Json::obj()
            .set(
                "uri",
                Json::str(format!("basalt://{VAULT_ID}/Notes/Start%20Here.md")),
            )
            .build(),
    );
    let contents = read
        .get("result")
        .and_then(|r| r.get("contents"))
        .and_then(|c| c.as_array())
        .expect("resources/read answers");
    assert_eq!(
        contents[0].get("mimeType").and_then(|m| m.as_str()),
        Some("text/markdown")
    );
    assert!(contents[0]
        .get("text")
        .and_then(|t| t.as_str())
        .unwrap()
        .contains("Start"));

    // A binary node comes back as a blob rather than as lossy text.
    let binary = rpc(
        &gk,
        "resources/read",
        Json::obj()
            .set(
                "uri",
                Json::str(format!("basalt://{VAULT_ID}/Assets/diagram.png")),
            )
            .build(),
    );
    assert!(binary
        .get("result")
        .and_then(|r| r.get("contents"))
        .and_then(|c| c.as_array())
        .and_then(|c| c[0].get("blob"))
        .is_some());
}

/// INTEROP §1.3: a `tools/call` denial is a tool result the model can read,
/// while `resources/read` fails as a JSON-RPC error.
#[test]
fn mcp_denials_follow_the_annex() {
    let gk = gatekeeper_for("u:reader");

    let denied = tool_call(
        &gk,
        "basalt_node",
        Json::obj()
            .set("path", Json::str("Notes/Columns.md"))
            .build(),
    );
    let result = denied.get("result").expect("a denial is still a result");
    assert_eq!(result.get("isError"), Some(&Json::Bool(true)));
    let text = result
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|c| c[0].get("text"))
        .and_then(|t| t.as_str())
        .unwrap();
    assert_eq!(
        parse_json(text).unwrap().get("error").and_then(|e| e.as_str()),
        Some("forbidden")
    );

    let unknown = tool_call(&gk, "basalt_drop_everything", Json::obj().build());
    assert_eq!(
        unknown
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| match c {
                Json::Int(i) => Some(*i),
                _ => None,
            }),
        Some(-32602)
    );

    let forbidden = rpc(
        &gk,
        "resources/read",
        Json::obj()
            .set(
                "uri",
                Json::str(format!("basalt://{VAULT_ID}/Notes/Columns.md")),
            )
            .build(),
    );
    assert_eq!(
        forbidden
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str()),
        Some("forbidden")
    );

    // A client holding several vaults open must not cross them.
    let foreign = rpc(
        &gk,
        "resources/read",
        Json::obj()
            .set("uri", Json::str("basalt://SOMEOTHERVAULT/Notes/Hexes.md"))
            .build(),
    );
    assert!(foreign.get("error").is_some(), "a foreign vault id was accepted");

    // A notification is never answered.
    let notification = Json::obj()
        .set("jsonrpc", Json::str("2.0"))
        .set("method", Json::str("notifications/initialized"))
        .build();
    let r = gk.handle_with_body(
        &request("POST", "/mcp"),
        notification.to_compact_string().as_bytes(),
    );
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty(), "a notification was answered");

    // There is no SSE stream to open: the GET half of Streamable HTTP would
    // stay silent, so it says so instead.
    assert_eq!(get(&gk, "/mcp").status, 405);
}

// -------------------------------------------------- equivalence (INTEROP §9)

/// The readable node set, asked of every mounted surface.
fn node_sets(principal: &str) -> BTreeMap<&'static str, Vec<String>> {
    let gk = gatekeeper_for(principal);
    let mut out = BTreeMap::new();

    let rest = body_of(&get(&gk, "/api/v1/nodes"));
    out.insert(
        "rest",
        sorted(
            rest.get("entries")
                .and_then(|e| e.as_array())
                .unwrap_or(&[])
                .iter()
                .filter_map(|e| e.get("path").and_then(|p| p.as_str()).map(String::from))
                .collect(),
        ),
    );

    let tool = tool_call(&gk, "basalt_nodes", Json::obj().build());
    let payload = parse_json(
        tool.get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|c| c[0].get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("null"),
    )
    .unwrap_or(Json::Null);
    out.insert(
        "mcp_tool",
        sorted(
            payload
                .get("entries")
                .and_then(|e| e.as_array())
                .unwrap_or(&[])
                .iter()
                .filter_map(|e| e.get("path").and_then(|p| p.as_str()).map(String::from))
                .collect(),
        ),
    );

    let resources = rpc(&gk, "resources/list", Json::obj().build());
    out.insert(
        "mcp_resources",
        sorted(
            resources
                .get("result")
                .and_then(|r| r.get("resources"))
                .and_then(|r| r.as_array())
                .unwrap_or(&[])
                .iter()
                .filter_map(|r| r.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect(),
        ),
    );
    out
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// E1: which nodes can this principal see? Every surface must agree, and the
/// expected sets come from the corpus.
#[test]
fn equivalence_visible_node_set() {
    let doc = load("cases/interop/equivalence.yaml");
    let case = support::cases(&doc)
        .into_iter()
        .find(|c| s(c, "id").as_deref() == Some("E1-visible-set"))
        .expect("the corpus holds E1");
    let expect = case.get("expect").expect("E1 names the expected sets");

    let mut r = Report::default();
    for principal in ["u:carter", "u:reader", "anonymous"] {
        let want = {
            let mut v: Vec<String> = expect
                .get(principal)
                .and_then(|x| x.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|i| i.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            v.sort();
            v
        };
        for (surface, got) in node_sets(principal) {
            r.check(
                &format!("{principal} via {surface}"),
                "visible node set",
                got,
                want.clone(),
            );
        }
    }
    r.finish("interop/E1");
}

/// E2: one node reads identically on every surface, redaction included.
#[test]
fn equivalence_same_node_everywhere() {
    let gk = gatekeeper_for("u:reader");
    let path = "Notes/Hexes.md";

    let rest = body_of(&get(&gk, &format!("/api/v1/node/{path}")));
    let raw = get(&gk, &format!("/api/v1/raw/{path}"));
    let tool = parse_json(
        tool_call(
            &gk,
            "basalt_node",
            Json::obj().set("path", Json::str(path)).build(),
        )
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
        .and_then(|c| c[0].get("text"))
        .and_then(|t| t.as_str())
        .unwrap(),
    )
    .unwrap();
    let resource = rpc(
        &gk,
        "resources/read",
        Json::obj()
            .set("uri", Json::str(format!("basalt://{VAULT_ID}/Notes/Hexes.md")))
            .build(),
    );

    let text = rest.get("text").and_then(|t| t.as_str()).unwrap();
    assert_eq!(tool.get("text").and_then(|t| t.as_str()), Some(text));
    assert_eq!(
        resource
            .get("result")
            .and_then(|r| r.get("contents"))
            .and_then(|c| c.as_array())
            .and_then(|c| c[0].get("text"))
            .and_then(|t| t.as_str()),
        Some(text)
    );
    assert_eq!(String::from_utf8_lossy(&raw.body), text, "/raw differs");
    assert_eq!(
        tool.get("node").and_then(|n| n.get("title")),
        rest.get("node").and_then(|n| n.get("title"))
    );

    // §9.5: the redacted edge looks the same on both surfaces, sentinel and all.
    let redacted_to = |value: &Json| -> Option<String> {
        value
            .get("links")
            .and_then(|l| l.get("out"))
            .and_then(|o| o.as_array())
            .and_then(|edges| {
                edges
                    .iter()
                    .find(|e| e.get("raw").and_then(|r| r.as_str()) == Some("Columns"))
                    .and_then(|e| e.get("to").and_then(|t| t.as_str()).map(String::from))
            })
    };
    assert_eq!(redacted_to(&rest).as_deref(), Some("redacted"));
    assert_eq!(redacted_to(&tool).as_deref(), Some("redacted"));
}

/// E3 and E4: both denials mean the same thing on every surface, and they
/// never swap — a 403 on a path the requester could not discover confirms it.
#[test]
fn equivalence_denials_agree() {
    let gk = gatekeeper_for("u:reader");
    for (path, fault) in [
        ("Notes/Columns.md", Fault::Forbidden),
        ("Notes/Nope.md", Fault::NotFound),
    ] {
        let rest = get(&gk, &format!("/api/v1/node/{path}"));
        assert_eq!(rest.status, fault.status(), "rest {path}");
        assert_eq!(
            body_of(&rest).get("error").and_then(|e| e.as_str()),
            Some(fault.code()),
            "rest {path}"
        );

        let tool = tool_call(
            &gk,
            "basalt_node",
            Json::obj().set("path", Json::str(path)).build(),
        );
        let text = tool
            .get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|c| c[0].get("text"))
            .and_then(|t| t.as_str())
            .unwrap();
        let payload = parse_json(text).unwrap();
        assert_eq!(
            payload.get("error").and_then(|e| e.as_str()),
            Some(fault.code()),
            "mcp {path}"
        );
        assert_eq!(
            payload.get("status"),
            Some(&Json::Int(fault.status() as i64)),
            "mcp {path}"
        );
    }
}

/// E5: no surface serves the protocol's own trees, not even to the owner —
/// they are the indexes, the ACLs and the principal list (§8.8, §12.4).
#[test]
fn equivalence_withheld_trees() {
    let gk = gatekeeper_for("u:carter");
    let doc = load("cases/interop/equivalence.yaml");
    let case = support::cases(&doc)
        .into_iter()
        .find(|c| s(c, "id").as_deref() == Some("E5-withheld"))
        .expect("the corpus holds E5");

    let mut r = Report::default();
    for target in list(&case, "paths") {
        for route in ["node", "raw", "links"] {
            let resp = get(&gk, &format!("/api/v1/{route}/{target}"));
            r.check(&target, &format!("rest {route}"), resp.status, 404);
        }
        let tool = tool_call(
            &gk,
            "basalt_node",
            Json::obj().set("path", Json::str(&target)).build(),
        );
        let text = tool
            .get("result")
            .and_then(|x| x.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|c| c[0].get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("null");
        r.check(
            &target,
            "mcp tool",
            parse_json(text)
                .unwrap_or(Json::Null)
                .get("error")
                .and_then(|e| e.as_str())
                .map(String::from),
            Some("not_found".to_string()),
        );
        let resource = rpc(
            &gk,
            "resources/read",
            Json::obj()
                .set("uri", Json::str(format!("basalt://{VAULT_ID}/{target}")))
                .build(),
        );
        r.check(
            &target,
            "mcp resource",
            resource
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(String::from),
            Some("not_found".to_string()),
        );
    }

    // Nor by listing: the reserved prefixes must not appear as content.
    for principal in ["u:carter", "u:reader"] {
        for (surface, paths) in node_sets(principal) {
            for p in paths {
                r.check(
                    &format!("{principal} via {surface}"),
                    &format!("{p} is content"),
                    !["index/", "meta/", "principals/", "history/"]
                        .iter()
                        .any(|pre| p.starts_with(pre)),
                    true,
                );
            }
        }
    }
    r.finish("interop/E5");
}

/// E6: warming the cache as one principal never serves it to another — in
/// both orders, because a cache keyed on anything less than the subject set
/// serves whichever principal arrived first.
#[test]
fn equivalence_cache_isolation() {
    let probes: Vec<(&str, fn(&Gatekeeper, &str) -> Vec<String>)> = vec![
        ("rest", |gk, _p| {
            let body = body_of(&get(gk, "/api/v1/list/Notes/"));
            body.get("entries")
                .and_then(|e| e.as_array())
                .unwrap_or(&[])
                .iter()
                .filter_map(|e| e.get("path").and_then(|p| p.as_str()).map(String::from))
                .collect()
        }),
        ("mcp_tool", |gk, _p| {
            let tool = tool_call(
                gk,
                "basalt_list",
                Json::obj().set("folder", Json::str("Notes/")).build(),
            );
            let text = tool
                .get("result")
                .and_then(|r| r.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|c| c[0].get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("null");
            parse_json(text)
                .unwrap_or(Json::Null)
                .get("entries")
                .and_then(|e| e.as_array())
                .unwrap_or(&[])
                .iter()
                .filter_map(|e| e.get("path").and_then(|p| p.as_str()).map(String::from))
                .collect()
        }),
        ("mcp_resources", |gk, _p| {
            rpc(gk, "resources/list", Json::obj().build())
                .get("result")
                .and_then(|r| r.get("resources"))
                .and_then(|r| r.as_array())
                .unwrap_or(&[])
                .iter()
                .filter_map(|r| r.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        }),
    ];

    let mut r = Report::default();
    for (name, probe) in probes {
        for order in [["u:carter", "u:reader"], ["u:reader", "u:carter"]] {
            // One gatekeeper, so one cache: the second request has to be
            // answered for its own principal, not from the first one's entry.
            // Mounts every surface: this probe compares REST against the MCP
            // tool and resource surfaces, so all three have to be reachable.
            let gk = Gatekeeper::new(vault())
                .with_surfaces(SurfaceKind::ALL.into_iter().collect())
                .with_identify(std::sync::Arc::new({
                let state = std::sync::Mutex::new(order.to_vec().into_iter());
                move |_: &Request| {
                    state
                        .lock()
                        .unwrap()
                        .next()
                        .unwrap_or("anonymous")
                        .to_string()
                }
            }));
            // `with_identify` hands out the principals in order, one per
            // request, which is exactly the interleaving §12.5 warns about.
            let first = probe(&gk, order[0]);
            let second = probe(&gk, order[1]);
            let secret = |set: &[String]| set.iter().any(|p| p.contains("Columns"));
            r.check(
                &format!("{name} {}", order[0]),
                "sees its own view first",
                secret(&first),
                order[0] == "u:carter",
            );
            r.check(
                &format!("{name} {}", order[1]),
                "is not served the first principal's view",
                secret(&second),
                order[1] == "u:carter",
            );
        }
    }
    r.finish("interop/E6");
}

// --------------------------------------------------- profiles (INTEROP §10)

/// §3.1: `publish.interop` is a ceiling. Present, a gatekeeper must not mount
/// a surface the vault does not list; absent, the vault claims nothing and the
/// operator decides.
#[test]
fn manifest_bounds_the_mounted_surfaces() {
    let mut v = vault();
    v.manifest.interop = Some(vec!["P-REST".into(), "P-INTEROP".into()]);
    let gk = Gatekeeper::new(v).with_fixed_principal("u:reader");
    assert!(gk.router().has(SurfaceKind::Rest));
    assert!(
        !gk.router().has(SurfaceKind::Mcp),
        "a surface the vault does not declare was mounted"
    );
    assert_eq!(get(&gk, "/api/v1/manifest").status, 200);
    let mcp = gk.handle_with_body(&request("POST", "/mcp"), b"{}");
    assert_eq!(mcp.status, 404, "an undeclared surface must 404, not answer");

    let discovery = body_of(&get(&gk, "/.well-known/basalt"));
    let surfaces = discovery
        .get("surfaces")
        .and_then(|s| s.as_object())
        .expect("the discovery document lists surfaces");
    assert_eq!(surfaces.keys().collect::<Vec<_>>(), vec!["rest"]);

    // A manifest that says nothing gets the §12 read surface and nothing
    // else. Profiles are opt-in (§14.1): silence means deny everywhere else
    // in this protocol, and a vault written before a profile existed cannot
    // have consented to serving it.
    let mut silent = vault();
    silent.manifest.interop = None;
    let quiet = Gatekeeper::new(silent).with_fixed_principal("u:reader");
    assert!(quiet.router().has(SurfaceKind::Rest));
    assert!(
        !quiet.router().has(SurfaceKind::Mcp),
        "a silent manifest must not mount interop profiles"
    );

    // The operator may serve less than the vault allows.
    let narrowed = Gatekeeper::new(vault())
        .with_surfaces(BTreeSet::from([SurfaceKind::Mcp]))
        .with_fixed_principal("u:reader");
    assert_eq!(get(&narrowed, "/api/v1/manifest").status, 404);
}

/// INTEROP §1.4: one document names every mounted surface and the operations
/// behind them, and it is the same for every principal because it describes
/// surfaces rather than content.
#[test]
fn discovery_document_describes_the_server() {
    let reader = body_of(&get(&gatekeeper_for("u:reader"), "/.well-known/basalt"));
    let owner = body_of(&get(&gatekeeper_for("u:carter"), "/.well-known/basalt"));
    assert_eq!(reader, owner, "discovery leaked something principal-shaped");

    assert_eq!(
        strings(reader.get("operations").unwrap()),
        OPERATIONS
            .iter()
            .map(|o| o.name.to_string())
            .collect::<Vec<_>>()
    );
    let surfaces = reader.get("surfaces").and_then(|s| s.as_object()).unwrap();
    assert_eq!(surfaces.keys().collect::<Vec<_>>(), vec!["mcp", "rest"]);
    assert!(surfaces
        .get("rest")
        .and_then(|r| r.get("openapi"))
        .and_then(|o| o.as_str())
        .unwrap()
        .ends_with("/api/v1/openapi.json"));
}

/// The server really speaks both surfaces over TCP, not just the handler —
/// MCP posts a body, which the §12 listener used to drain.
#[test]
fn serves_both_surfaces_over_tcp() {
    use std::io::{Read, Write};
    use std::sync::Arc;

    let gk = Arc::new(gatekeeper_for("u:reader"));
    let listener = Gatekeeper::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || gk.serve(listener));

    let call = |raw: String| -> String {
        let mut sock = std::net::TcpStream::connect(addr).unwrap();
        sock.write_all(raw.as_bytes()).unwrap();
        let mut buf = String::new();
        sock.read_to_string(&mut buf).unwrap();
        buf
    };

    let rest = call("GET /api/v1/manifest HTTP/1.1\r\nhost: localhost\r\n\r\n".into());
    assert!(rest.starts_with("HTTP/1.1 200 OK"), "{rest}");
    assert!(rest.contains("x-basalt-surface: rest"), "{rest}");

    let message = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let mcp = call(format!(
        "POST /mcp HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{message}",
        message.len()
    ));
    assert!(mcp.starts_with("HTTP/1.1 200 OK"), "{mcp}");
    assert!(mcp.contains("basalt_search"), "{mcp}");
    assert!(mcp.contains("mcp-protocol-version:"), "{mcp}");

    // A HEAD carries the headers of the GET and none of the body.
    let head = call("HEAD /api/v1/manifest HTTP/1.1\r\nhost: localhost\r\n\r\n".into());
    assert!(head.contains("etag:"), "{head}");
    assert!(!head.contains("\"basalt\""), "{head}");
}

/// E8: the shape invariants, read out of the corpus.
///
/// Each of these was a disagreement found by running this implementation and
/// the TypeScript one side by side against `vaults/minimal` and diffing the
/// answers. None was a §8 failure — each was one implementation shaping a
/// reply its own way — and each would have broken a client that switched
/// implementations. The corpus owns the rule; this is the half that holds
/// this implementation to it.
#[test]
fn equivalence_shape_invariants() {
    let doc = load("cases/interop/equivalence.yaml");
    let case = support::cases(&doc)
        .into_iter()
        .find(|c| s(c, "id").as_deref() == Some("E8-shape-invariants"))
        .expect("the corpus holds E8");
    let invariants = case
        .get("invariants")
        .and_then(|i| i.as_sequence())
        .expect("E8 lists invariants");

    let gk = gatekeeper_for("u:reader");
    let me = body_of(&get(&gk, "/api/v1/me"));
    let tags = body_of(&get(&gk, "/api/v1/tags"));
    let links = body_of(&get(&gk, "/api/v1/links/Notes/Hexes.md"));
    let node = body_of(&get(&gk, "/api/v1/node/Notes/Hexes.md"));
    let manifest = body_of(&get(&gk, "/api/v1/manifest"));

    let mut r = Report::default();
    for inv in invariants {
        let id = s(inv, "id").expect("each invariant has an id");
        match id.as_str() {
            "subjects-sorted" => {
                let got = strings(me.get("subjects").unwrap());
                let mut want = got.clone();
                want.sort();
                r.check(&id, "subject set order", got, want);
            }
            "display-name-from-display" => {
                r.check(
                    &id,
                    "display_name",
                    me.get("display_name").and_then(|d| d.as_str()),
                    Some("A Reader"),
                );
            }
            "tags-sorted" => {
                let got: Vec<String> = tags
                    .get("tags")
                    .and_then(|t| t.as_array())
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|t| t.get("tag").and_then(|x| x.as_str()).map(String::from))
                    .collect();
                let mut want = got.clone();
                want.sort();
                r.check(&id, "tag posting order", got, want);
            }
            "edge-target-present" => {
                for edge in links.get("out").and_then(|o| o.as_array()).unwrap_or(&[]) {
                    let raw = edge.get("raw").and_then(|x| x.as_str()).unwrap_or("?");
                    r.check(&id, &format!("{raw} carries target"), edge.get("target").is_some(), true);
                }
                let dangling = links
                    .get("out")
                    .and_then(|o| o.as_array())
                    .unwrap_or(&[])
                    .iter()
                    .find(|e| e.get("raw").and_then(|x| x.as_str()) == Some("Does Not Exist"));
                r.check(
                    &id,
                    "an unresolved edge has an explicit null target",
                    dangling.and_then(|e| e.get("target")),
                    Some(&Json::Null),
                );
            }
            "node-links-is-a-linkset" => {
                let embedded = node.get("links").expect("node carries links");
                r.check(
                    &id,
                    "node.links.path",
                    embedded.get("path").and_then(|p| p.as_str()),
                    Some("Notes/Hexes.md"),
                );
                r.check(
                    &id,
                    "node.links has the link route's fields",
                    embedded.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>()),
                    links.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>()),
                );
            }
            "index-state-is-honest" => {
                let state = manifest.get("index_state").and_then(|x| x.as_str());
                r.check(
                    &id,
                    "index_state is one of the three §10.6 values",
                    ["fresh", "stale", "rebuilt"].contains(&state.unwrap_or("")),
                    true,
                );
            }
            other => r.check(other, "has a check in this runner", false, true),
        }
    }
    r.finish("interop/E8");
}
