//! The gatekeeper HTTP surface, PROTOCOL §12.
//!
//! §12.5 names the cache as "the single most likely place for a
//! conforming-looking implementation to leak", and says §14 tests it directly.
//! That test is [`cache_is_keyed_by_subject_set`], and it is the reason this
//! file exists at all.

mod support;

use basalt::canonical::parse_json;
use basalt::gatekeeper::{Delivery, Gatekeeper, Request, Response};
use basalt::transport::FsTransport;
use basalt::vault::{IndexState, Vault};
use std::collections::BTreeMap;
use std::sync::Arc;

fn gatekeeper_for(principal: &str) -> Gatekeeper {
    let dir = support::conformance_dir().join("vaults/minimal/vault");
    let mut v = Vault::open(Box::new(FsTransport::new(&dir))).expect("vault opens");
    v.reindex(false).expect("reindex");
    Gatekeeper::new(v).with_fixed_principal(principal)
}

fn get(gk: &Gatekeeper, path: &str) -> Response {
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
    gk.handle(&Request {
        method: "GET".into(),
        path: p,
        query: q,
        headers: BTreeMap::new(),
    })
}

fn header(r: &Response, name: &str) -> Option<String> {
    r.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// §12.3: every response carries `X-Basalt-Index-State` and `X-Basalt-Vault`.
#[test]
fn every_response_declares_vault_and_index_state() {
    let gk = gatekeeper_for("u:carter");
    gk.set_index_state(IndexState::Rebuilt);
    let r = get(&gk, "/api/v1/manifest");
    assert_eq!(r.status, 200);
    assert_eq!(
        header(&r, "x-basalt-vault").as_deref(),
        Some("01JBQ7X8Z4N3VYK9M2T5HRWC6P")
    );
    assert_eq!(
        header(&r, "x-basalt-index-state").as_deref(),
        Some("rebuilt")
    );
    // §12.4: an ACL-filtered response must never enter a shared cache.
    assert_eq!(
        header(&r, "cache-control").as_deref(),
        Some("private, no-store")
    );

    // Even a denial carries them, so a client is never left guessing.
    let denied = get(&gk, "/api/v1/node/Notes/Nope.md");
    assert_eq!(denied.status, 404);
    assert!(header(&denied, "x-basalt-index-state").is_some());
}

/// §12.3: `manifest` returns the *public subset*. §15 notes that `security.*`
/// discloses the vault's whole enforcement posture.
#[test]
fn manifest_route_hides_the_security_block() {
    let gk = gatekeeper_for("u:carter");
    let body = String::from_utf8(get(&gk, "/api/v1/manifest").body).unwrap();
    assert!(body.contains("01JBQ7X8Z4N3VYK9M2T5HRWC6P"));
    assert!(body.contains("gated"));
    assert!(!body.contains("bypass_traverse"), "{body}");
    assert!(!body.contains("deny_unresolved"), "{body}");
}

/// §12.4: the protocol's own trees MUST NEVER be served to a non-`system`
/// principal, and §8.8 explains why — the indexes know everything.
#[test]
fn protocol_trees_are_never_served() {
    let gk = gatekeeper_for("u:carter");
    for target in [
        "index/nodes.json",
        "index/search.json",
        "meta/acl/acl.yaml",
        "principals/users.yaml",
        "history/x/1.json",
        "basalt.yaml",
    ] {
        for route in ["node", "raw"] {
            let r = get(&gk, &format!("/api/v1/{route}/{target}"));
            // 404, not 403: a 403 would itself confirm the tree is there.
            assert_eq!(r.status, 404, "{route}/{target} must be 404");
        }
    }
}

/// §12.3: the 404/403 split, over HTTP this time.
#[test]
fn denial_semantics_over_http() {
    let reader = gatekeeper_for("u:reader");
    let owner = gatekeeper_for("u:carter");
    let anon = gatekeeper_for("anonymous");

    // u:reader may list Notes/ and so may know Columns.md exists: 403.
    assert_eq!(get(&reader, "/api/v1/node/Notes/Columns.md").status, 403);
    // The owner reads it.
    assert_eq!(get(&owner, "/api/v1/node/Notes/Columns.md").status, 200);
    // A path that does not exist: 404.
    assert_eq!(get(&owner, "/api/v1/node/Notes/Nope.md").status, 404);
    // Anonymous, stopped by the gated ceiling (§12.2) before the DACL, cannot
    // discover anything: 404 throughout.
    assert_eq!(get(&anon, "/api/v1/node/Notes/Hexes.md").status, 404);
    assert_eq!(get(&anon, "/api/v1/node/Notes/Columns.md").status, 404);
}

/// §12.3: `list` is filtered to entries the principal may see, and §15 asks
/// that counts of invisible entries be omitted rather than reported.
#[test]
fn list_is_filtered_without_leaking_counts() {
    let reader = gatekeeper_for("u:reader");
    let owner = gatekeeper_for("u:carter");

    let r = get(&reader, "/api/v1/list/Notes/");
    assert_eq!(r.status, 200);
    let body = parse_json(&String::from_utf8(r.body).unwrap()).unwrap();
    let paths: Vec<String> = body
        .get("entries")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.get("path").unwrap().as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        paths,
        vec!["Notes/Hexes.md", "Notes/Start Here.md"],
        "the private Columns.md is absent"
    );
    assert!(
        !String::from_utf8(get(&reader, "/api/v1/list/Notes/").body)
            .unwrap()
            .contains("hidden"),
        "no count of what was pruned"
    );

    let r = get(&owner, "/api/v1/list/Notes/");
    let body = parse_json(&String::from_utf8(r.body).unwrap()).unwrap();
    assert_eq!(body.get("entries").unwrap().as_array().unwrap().len(), 3);
}

/// §12.5: the cache key MUST include the principal's effective subject set, or
/// the cache serves one user's visibility to another.
///
/// Two gatekeepers would not share a cache, so this drives *one* instance with
/// an `identify` that switches principal per request — which is exactly the
/// shape of a real deployment and exactly where the leak would happen.
#[test]
fn cache_is_keyed_by_subject_set() {
    let dir = support::conformance_dir().join("vaults/minimal/vault");
    let mut v = Vault::open(Box::new(FsTransport::new(&dir))).unwrap();
    v.reindex(false).unwrap();

    // The principal comes from a header the gatekeeper itself trusts — stands
    // in for the session a real deployment would read (§12.1).
    let gk = Gatekeeper::new(v).with_identify(Arc::new(|req: &Request| {
        req.header("x-test-principal")
            .unwrap_or("anonymous")
            .to_string()
    }));

    let as_who = |who: &str| {
        let mut headers = BTreeMap::new();
        headers.insert("x-test-principal".to_string(), who.to_string());
        gk.handle(&Request {
            method: "GET".into(),
            path: "/api/v1/list/Notes/".into(),
            query: BTreeMap::new(),
            headers,
        })
    };

    // Warm the cache as the owner, who can see the private note…
    let owner_body = String::from_utf8(as_who("u:carter").body).unwrap();
    assert!(owner_body.contains("Notes/Columns.md"));

    // …then ask as a reader who must not. A cache keyed only by route would
    // hand back the owner's answer here.
    let reader_body = String::from_utf8(as_who("u:reader").body).unwrap();
    assert!(
        !reader_body.contains("Notes/Columns.md"),
        "§12.5 leak: the cache served one principal's visibility to another:\n{reader_body}"
    );

    // And the owner's own second request is still served correctly.
    assert!(String::from_utf8(as_who("u:carter").body)
        .unwrap()
        .contains("Notes/Columns.md"));

    // The same for `tree`, the other cached route.
    let tree_of = |who: &str| {
        let mut headers = BTreeMap::new();
        headers.insert("x-test-principal".to_string(), who.to_string());
        String::from_utf8(
            gk.handle(&Request {
                method: "GET".into(),
                path: "/api/v1/tree".into(),
                query: BTreeMap::new(),
                headers,
            })
            .body,
        )
        .unwrap()
    };
    assert!(tree_of("u:carter").contains("Notes/Columns.md"));
    assert!(!tree_of("u:reader").contains("Notes/Columns.md"));
}

/// §12.3 and §9.5: `links` is redacted rather than pruned.
#[test]
fn links_route_redacts() {
    let gk = gatekeeper_for("u:reader");
    let r = get(&gk, "/api/v1/links/Notes/Start Here.md");
    assert_eq!(r.status, 200);
    let body = String::from_utf8(r.body).unwrap();
    assert!(body.contains("\"redacted\""), "the edge survives: {body}");
    assert!(
        !body.contains("Notes/Columns.md"),
        "but its target does not: {body}"
    );
}

/// §12.3: `effective` is a privileged view — §8.7's own route requires
/// `read_acl` on the object.
#[test]
fn effective_route_requires_read_acl() {
    let reader = gatekeeper_for("u:reader");
    let owner = gatekeeper_for("u:carter");

    let r = get(&reader, "/api/v1/effective?path=Notes/Columns.md");
    assert_eq!(r.status, 403, "u:reader has no read_acl");

    let r = get(&owner, "/api/v1/effective?path=Notes/Columns.md");
    assert_eq!(r.status, 200);
    let body = parse_json(&String::from_utf8(r.body).unwrap()).unwrap();
    assert!(body
        .get("granted")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g.as_str() == Some("read")));
    // And the deciding ACE is reported per right, which is the whole value of
    // the route (§8.7).
    let decision = body
        .get("decisions")
        .and_then(|d| d.get("read"))
        .and_then(|d| d.get("by"))
        .and_then(|b| b.as_str())
        .unwrap();
    assert_eq!(decision, "allow:u:carter");
}

/// §12.5: search postings are filtered to readable nodes. The minimal vault
/// grants `read` to nobody anonymously, so its `search.json` is empty by §8.8
/// and this route has nothing to leak — which is itself the assertion.
#[test]
fn search_route_is_filtered() {
    let gk = gatekeeper_for("u:carter");
    let r = get(&gk, "/api/v1/search?q=hexagons");
    assert_eq!(r.status, 200);
    let body = parse_json(&String::from_utf8(r.body).unwrap()).unwrap();
    assert!(body.get("hits").unwrap().as_array().unwrap().is_empty());

    assert_eq!(get(&gk, "/api/v1/search").status, 400, "q is required");
}

/// §12.3: the surface is read-only.
#[test]
fn writes_are_rejected() {
    let gk = gatekeeper_for("u:carter");
    let r = gk.handle(&Request {
        method: "PUT".into(),
        path: "/api/v1/node/Notes/Hexes.md".into(),
        query: BTreeMap::new(),
        headers: BTreeMap::new(),
    });
    assert_eq!(r.status, 405);
}

/// §12.4: without `presign`, redirect delivery falls back to proxying rather
/// than failing — a filesystem vault has no URL to mint.
#[test]
fn raw_proxies_when_presign_is_unavailable() {
    let dir = support::conformance_dir().join("vaults/minimal/vault");
    let mut v = Vault::open(Box::new(FsTransport::new(&dir))).unwrap();
    v.reindex(false).unwrap();
    let gk = Gatekeeper::new(v)
        .with_fixed_principal("u:carter")
        .with_delivery(Delivery::Redirect);

    let r = get(&gk, "/api/v1/raw/Assets/diagram.png");
    assert_eq!(r.status, 200, "proxied, not redirected");
    assert_eq!(r.body, b"PNG-PLACEHOLDER-BYTES\n");
    assert_eq!(header(&r, "content-type").as_deref(), Some("image/png"));
}

/// §10.6: a gatekeeper MUST signal staleness under every policy, and `refuse`
/// answers with an error rather than data.
#[test]
fn stale_policy_refuse_declines() {
    let dir = support::conformance_dir().join("vaults/minimal/vault");
    let mut v = Vault::open(Box::new(FsTransport::new(&dir))).unwrap();
    v.reindex(false).unwrap();
    v.manifest.stale_policy = basalt::manifest::StalePolicy::Refuse;
    let gk = Gatekeeper::new(v).with_fixed_principal("u:carter");
    gk.set_index_state(IndexState::Stale);

    let r = get(&gk, "/api/v1/node/Notes/Hexes.md");
    assert_eq!(r.status, 503);
    assert_eq!(header(&r, "x-basalt-index-state").as_deref(), Some("stale"));
}

/// The server really speaks HTTP, not just the handler.
#[test]
fn serves_over_tcp() {
    use std::io::{Read, Write};
    let gk = Arc::new(gatekeeper_for("u:carter"));
    let listener = Gatekeeper::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || gk.serve(listener));

    let mut sock = std::net::TcpStream::connect(addr).unwrap();
    sock.write_all(b"GET /api/v1/manifest HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .unwrap();
    let mut buf = String::new();
    sock.read_to_string(&mut buf).unwrap();
    assert!(buf.starts_with("HTTP/1.1 200 OK"), "{buf}");
    assert!(
        buf.contains("x-basalt-vault: 01JBQ7X8Z4N3VYK9M2T5HRWC6P"),
        "{buf}"
    );
    assert!(buf.contains("01JBQ7X8Z4N3VYK9M2T5HRWC6P"));
}
