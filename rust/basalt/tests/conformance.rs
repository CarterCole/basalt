//! The language-neutral corpus for L0-L2, PROTOCOL §14.2.

mod support;

use basalt::frontmatter::parse_note;
use basalt::keys::{
    find_collisions, find_folder_case_divergence, implied_folders, key_to_path, validate_key,
};
use basalt::links::{anchor_resolves, extract_links, ResolvableNode, Resolver};
use support::*;

// ------------------------------------------------------------ L0: keys

#[test]
fn keys_validation() {
    let doc = load("cases/keys/validation.yaml");
    let mut r = Report::default();
    for c in cases(&doc) {
        let name = s(&c, "name").unwrap();
        let key = s(&c, "key").unwrap_or_default();
        let valid = b(&c, "valid").unwrap_or(false);
        match validate_key(&key) {
            Ok(()) => r.check(
                &name,
                "validity",
                "valid",
                if valid { "valid" } else { "rejected" },
            ),
            Err(e) => {
                if valid {
                    r.check(
                        &name,
                        "validity",
                        format!("rejected: {}", e.code.as_str()),
                        "valid",
                    );
                } else {
                    r.check(
                        &name,
                        "error code",
                        e.code.as_str(),
                        s(&c, "error").unwrap(),
                    );
                }
            }
        }
    }
    r.finish("keys/validation");
}

// ------------------------------------------------------- L1: collisions

#[test]
fn path_collisions() {
    let doc = load("cases/paths/collisions.yaml");
    let mut r = Report::default();
    for c in cases(&doc) {
        let name = s(&c, "name").unwrap();
        let keys = list(&c, "keys");
        let groups = find_collisions(keys.iter());
        if b(&c, "collides") == Some(true) {
            r.check(&name, "colliding group count", groups.len(), 1usize);
            if let Some(g) = groups.first() {
                // §2.2: the surviving key is deterministic, so a repair is
                // reproducible across implementations.
                r.check(&name, "survivor", g[0].clone(), s(&c, "survivor").unwrap());
            }
        } else {
            r.check(
                &name,
                "no collisions",
                groups.clone(),
                Vec::<Vec<String>>::new(),
            );
        }
        if present(&c, "folder_divergence") {
            let d = find_folder_case_divergence(keys.iter());
            r.check(&name, "folder divergence count", d.len(), 1usize);
            if let Some(g) = d.first() {
                r.check(
                    &name,
                    "folder divergence",
                    g.clone(),
                    list(&c, "folder_divergence"),
                );
            }
        }
    }
    r.finish("paths/collisions");
}

#[test]
fn implied_folder_sets() {
    let doc = load("cases/paths/folders.yaml");
    let mut r = Report::default();
    for c in cases(&doc) {
        let name = s(&c, "name").unwrap();
        let paths: Vec<String> = list(&c, "keys")
            .iter()
            .filter_map(|k| key_to_path(k).map(str::to_string))
            .collect();
        r.check(
            &name,
            "folders",
            implied_folders(&paths),
            list(&c, "folders"),
        );
    }
    r.finish("paths/folders");
}

// ------------------------------------------------------ L1: frontmatter

#[test]
fn frontmatter_parsing() {
    let doc = load("cases/frontmatter/parsing.yaml");
    let mut r = Report::default();
    for c in cases(&doc) {
        let name = s(&c, "name").unwrap();
        let content = s(&c, "content").unwrap_or_default();
        // No `path` means the case is not exercising the filename-stem title
        // fallback, so pass "" rather than inventing a name to fall back to.
        let path = s(&c, "path").unwrap_or_default();
        let got = parse_note(&content, &path);
        let want = c
            .get("expect")
            .cloned()
            .unwrap_or(serde_yaml_ng::Value::Null);

        if present(&want, "id") {
            r.check(&name, "id", got.id.clone(), opt_s(&want, "id"));
        }
        if present(&want, "title") {
            r.check(&name, "title", got.title.clone(), opt_s(&want, "title"));
        }
        if present(&want, "tags") {
            // §5.2: frontmatter `tags` merge with inline `#tags` from the
            // body, which is a property of the pair, so the runner merges them
            // exactly as the indexer does.
            let inline = extract_links(&got.body).tags;
            let mut merged = got.tags.clone();
            for t in inline {
                if !merged.contains(&t) {
                    merged.push(t);
                }
            }
            r.check(&name, "tags", merged, list(&want, "tags"));
        }
        if present(&want, "aliases") {
            r.check(
                &name,
                "aliases",
                got.aliases.clone(),
                list(&want, "aliases"),
            );
        }
        if present(&want, "publish") {
            r.check(&name, "publish", got.publish, b(&want, "publish").unwrap());
        }
        if present(&want, "body_starts_line") {
            r.check(
                &name,
                "body_starts_line",
                got.body_start_line as i64,
                n(&want, "body_starts_line").unwrap(),
            );
        }
        if let Some(errs) = want.get("errors").and_then(|e| e.as_sequence()) {
            let got_errs: Vec<(String, String)> = got
                .errors
                .iter()
                .map(|e| (e.severity.as_str().to_string(), e.code.clone()))
                .collect();
            let want_errs: Vec<(String, String)> = errs
                .iter()
                .map(|e| {
                    (
                        s(e, "severity").unwrap_or_default(),
                        s(e, "code").unwrap_or_default(),
                    )
                })
                .collect();
            r.check(&name, "errors", got_errs, want_errs);
        }
    }
    r.finish("frontmatter/parsing");
}

// --------------------------------------------------- L2: link extraction

#[test]
fn link_extraction() {
    let doc = load("cases/links/extraction.yaml");
    let mut r = Report::default();
    for c in cases(&doc) {
        let name = s(&c, "name").unwrap();
        let content = s(&c, "content").unwrap_or_default();
        let path = s(&c, "path").unwrap_or_else(|| "Notes/Source.md".into());
        let parsed = parse_note(&content, &path);
        let got = extract_links(&parsed.body);

        if let Some(want_edges) = c.get("edges").and_then(|e| e.as_sequence()) {
            r.check(
                &name,
                "edge count",
                got.edges.iter().map(|e| e.raw.clone()).collect::<Vec<_>>(),
                want_edges
                    .iter()
                    .map(|e| s(e, "raw").unwrap_or_default())
                    .collect::<Vec<_>>(),
            );
            for (i, want) in want_edges.iter().enumerate() {
                let Some(g) = got.edges.get(i) else { continue };
                let tag = format!("{name} edge {i}");
                r.check(&tag, "kind", g.kind.as_str(), s(want, "kind").unwrap());
                r.check(&tag, "raw", g.raw.clone(), s(want, "raw").unwrap());
                r.check(&tag, "alias", g.alias.clone(), opt_s(want, "alias"));
                r.check(&tag, "anchor", g.anchor.clone(), opt_s(want, "anchor"));
                if present(want, "line") {
                    r.check(&tag, "line", g.line as i64, n(want, "line").unwrap());
                }
            }
        }
        if present(&c, "tags") {
            let mut merged = parsed.tags.clone();
            for t in &got.tags {
                if !merged.contains(t) {
                    merged.push(t.clone());
                }
            }
            r.check(&name, "tags", merged, list(&c, "tags"));
        }
    }
    r.finish("links/extraction");
}

// -------------------------------------------------- L2: link resolution

#[test]
fn link_resolution() {
    let doc = load("cases/links/resolution.yaml");
    let nodes: Vec<ResolvableNode> = doc
        .get("vault")
        .and_then(|v| v.get("nodes"))
        .and_then(|n| n.as_sequence())
        .expect("resolution corpus declares a vault")
        .iter()
        .map(|n| ResolvableNode {
            id: s(n, "id").unwrap(),
            path: s(n, "path").unwrap(),
            aliases: list(n, "aliases"),
        })
        .collect();
    let resolver = Resolver::build(nodes);

    let mut r = Report::default();
    for c in cases(&doc) {
        let name = s(&c, "name").unwrap();
        let from = s(&c, "from").unwrap();
        let target = s(&c, "target").unwrap();
        // The anchor is stripped before resolution: §9.3 carries it on the
        // edge but it never affects which node resolves.
        let (bare, anchor) = match target.split_once('#') {
            Some((t, a)) => (t.to_string(), Some(a.to_string())),
            None => (target.clone(), None),
        };
        let got = resolver.resolve(&from, &bare);

        r.check(
            &name,
            "resolved node",
            got.id.clone(),
            opt_s(&c, "resolves_to"),
        );
        r.check(
            &name,
            "resolution step",
            got.by.as_str(),
            s(&c, "by").unwrap(),
        );
        if present(&c, "ambiguous") {
            r.check(
                &name,
                "ambiguity flag",
                got.ambiguous,
                b(&c, "ambiguous").unwrap(),
            );
        }
        if present(&c, "candidates") {
            r.check(
                &name,
                "candidate order",
                got.candidates.clone(),
                list(&c, "candidates"),
            );
        }
        if present(&c, "raw") {
            r.check(&name, "raw preserved", bare.clone(), s(&c, "raw").unwrap());
        }
        if present(&c, "anchor_resolved") {
            // The fixture vault carries no heading data, so an anchor naming
            // anything cannot resolve — which is the point: §9.3 says the edge
            // still resolves to the node.
            r.check(
                &name,
                "anchor_resolved",
                anchor_resolves(anchor.as_deref(), &[], &[]),
                b(&c, "anchor_resolved").unwrap(),
            );
        }
    }
    r.finish("links/resolution");
}
