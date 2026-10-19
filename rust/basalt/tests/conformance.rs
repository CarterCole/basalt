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

// ------------------------------------------------------- the inventory itself

/// `conformance/manifest.yaml` declares the case inventory (§14.2). This
/// asserts the runner actually sees every case the corpus claims, so a suite
/// that grows cannot be silently skipped by a runner that was written against
/// an older corpus — which is the failure mode that makes a conformance claim
/// worthless.
#[test]
fn corpus_inventory_matches() {
    let manifest = load("manifest.yaml");
    let mut r = Report::default();

    r.check(
        "manifest",
        "corpus major version",
        n(&manifest, "basalt"),
        Some(1i64),
    );

    for suite in manifest
        .get("suites")
        .and_then(|s| s.as_sequence())
        .expect("manifest declares suites")
    {
        let file = s(suite, "file").unwrap();
        let declared = n(suite, "cases").unwrap_or(0);
        let doc = load(&file);
        let actual = cases(&doc).len() as i64;

        // The property that matters is that nothing has gone missing: the
        // per-suite runners above iterate the *file*, so a case that exists is
        // always executed. A file with fewer cases than the manifest declares
        // means a case was dropped, which is a real regression.
        if actual < declared {
            r.check(&file, "cases present (none dropped)", actual, declared);
        } else {
            r.passed += 1;
        }
        // A surplus is bookkeeping drift in the manifest rather than a
        // conformance failure, so it is reported and not fatal.
        if actual > declared {
            eprintln!(
                "  note: {file} holds {actual} cases, manifest.yaml declares {declared} \
                 — all {actual} are executed; the manifest count is stale"
            );
        }
        r.check(&file, "level", s(&doc, "level"), s(suite, "level"));
        r.check(&file, "spec section", s(&doc, "spec"), s(suite, "spec"));
    }

    for vault in manifest
        .get("vaults")
        .and_then(|v| v.as_sequence())
        .unwrap_or(&vec![])
    {
        let dir = s(vault, "dir").unwrap();
        let path = conformance_dir().join(&dir).join("vault/basalt.yaml");
        r.check(&dir, "vault present", path.exists(), true);
    }

    r.finish("manifest inventory");
}

/// The levels this implementation claims (§14.1). An implementation declares
/// the levels it meets, and each requires all below it; this test exists so the
/// claim in `lib.rs` and `README.md` is checked rather than asserted.
///
/// L0 Transport, L1 Content, L2 Index, L3 Security and L4 Gatekeeper are
/// covered by the suites in this directory. L5 History is **not** implemented:
/// nothing here writes `history/`, so the claim stops at L4.
#[test]
fn declared_conformance_levels() {
    let manifest = load("manifest.yaml");
    let levels = manifest
        .get("levels")
        .and_then(|l| l.as_mapping())
        .expect("manifest names the levels");

    let claimed = ["L0", "L1", "L2", "L3", "L4"];
    for level in claimed {
        assert!(
            levels
                .get(serde_yaml_ng::Value::String(level.into()))
                .is_some(),
            "{level} is a level the corpus knows about"
        );
    }
    // Every suite at or below the claimed ceiling must be one this runner
    // executes. If the corpus adds, say, an L3 suite, this fails until the
    // runner covers it.
    let covered = [
        "cases/keys/validation.yaml",
        "cases/paths/collisions.yaml",
        "cases/paths/folders.yaml",
        "cases/frontmatter/parsing.yaml",
        "cases/links/extraction.yaml",
        "cases/links/resolution.yaml",
        "cases/acl/evaluation.yaml",
    ];
    for suite in manifest
        .get("suites")
        .and_then(|x| x.as_sequence())
        .unwrap()
    {
        let file = s(suite, "file").unwrap();
        let level = s(suite, "level").unwrap_or_default();
        if claimed.contains(&level.as_str()) {
            assert!(
                covered.contains(&file.as_str()),
                "the corpus has a {level} suite this runner does not execute: {file}\n\
                 Add it to tests/conformance.rs (or tests/acl.rs) before claiming {level}."
            );
        }
    }
}

/// The interop profiles this implementation claims (§17, INTEROP §10).
///
/// Profiles are orthogonal to the §14.1 levels and each requires L4, so they
/// are declared separately — and, like the levels above, checked rather than
/// asserted: `P-REST` and `P-MCP` are the two this crate serves, the corpus
/// has to know them, and the suite that exercises them has to be one this
/// runner executes.
#[test]
fn declared_interop_profiles() {
    let manifest = load("manifest.yaml");
    let profiles = manifest
        .get("profiles")
        .and_then(|p| p.as_mapping())
        .expect("manifest names the interop profiles");

    // P-INTEROP is the claim that the two below answer the same questions the
    // same way, which tests/interop.rs checks as INTEROP §9's E1-E6.
    let claimed = ["P-REST", "P-MCP", "P-INTEROP"];
    for profile in claimed {
        assert!(
            profiles
                .get(serde_yaml_ng::Value::String(profile.into()))
                .is_some(),
            "{profile} is a profile the corpus knows about"
        );
    }

    // What the crate mounts and what it claims must be the same list.
    let mounted: Vec<&str> = basalt::serve::router::SurfaceKind::ALL
        .iter()
        .map(|k| k.profile())
        .collect();
    for profile in &mounted {
        assert!(
            claimed.contains(profile),
            "{profile} is mounted but not claimed here"
        );
    }
    assert_eq!(mounted.len() + 1, claimed.len(), "P-INTEROP is the extra claim");

    // A profile suite the runner does not execute is a claim nobody checks.
    let interop_suites: Vec<String> = manifest
        .get("suites")
        .and_then(|x| x.as_sequence())
        .unwrap()
        .iter()
        .filter_map(|suite| s(suite, "file"))
        .filter(|file| file.starts_with("cases/interop/"))
        .collect();
    assert_eq!(
        interop_suites,
        vec![
            "cases/interop/surfaces.yaml".to_string(),
            "cases/interop/equivalence.yaml".to_string(),
        ],
        "tests/interop.rs executes exactly these; a new one needs a runner"
    );
}
