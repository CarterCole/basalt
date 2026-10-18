//! The language-neutral ACL corpus, PROTOCOL §14.2.
//!
//! Each case asserts the *deciding ACE*, not just the boolean. Two
//! implementations can agree on "denied" for different reasons and only one of
//! them is following §8.4, so a boolean-only assertion misses exactly the
//! band-ordering bug that matters.

mod support;

use basalt::acl::{Audience, Descriptor, EvalOpts, Group, Principals, User};
use basalt::security::{check_access, DescriptorStore, FolderAcl};
use serde_yaml_ng::Value as Yaml;
use std::collections::BTreeMap;
use support::*;

/// Turn a case's `descriptors` map into a store.
///
/// A key of `/` is the vault root, a key ending in `/` is a folder, and
/// anything else names a node — which goes in the inline map, since §8.6 gives
/// an inline descriptor precedence over a folder file's entry anyway.
fn build_store(descriptors: Option<&Yaml>) -> DescriptorStore {
    let mut store = DescriptorStore::new();
    let Some(Yaml::Mapping(m)) = descriptors else {
        return store;
    };
    for (k, v) in m {
        let Some(path) = k.as_str() else { continue };
        if path == "/" || path.ends_with('/') {
            let folder = if path == "/" { "" } else { path };
            store.folder_acls.insert(
                folder.to_string(),
                FolderAcl {
                    folder: Some(Descriptor::from_yaml(v)),
                    entries: BTreeMap::new(),
                },
            );
        } else {
            store
                .inline_acls
                .insert(path.to_string(), Descriptor::from_yaml(v));
        }
    }
    store
}

/// Deep-merge a case's `manifest` over the corpus `defaults.manifest`.
fn merge(base: Option<&Yaml>, over: Option<&Yaml>) -> Yaml {
    match (base, over) {
        (None, None) => Yaml::Null,
        (Some(b), None) => b.clone(),
        (None, Some(o)) => o.clone(),
        (Some(Yaml::Mapping(b)), Some(Yaml::Mapping(o))) => {
            let mut out = b.clone();
            for (k, v) in o {
                let merged = merge(b.get(k), Some(v));
                out.insert(k.clone(), merged);
            }
            Yaml::Mapping(out)
        }
        (_, Some(o)) => o.clone(),
    }
}

fn opts_for(defaults: Option<&Yaml>, case: &Yaml) -> EvalOpts {
    let m = merge(
        defaults.and_then(|d| d.get("manifest")),
        case.get("manifest"),
    );
    EvalOpts {
        audience: m
            .get("publish")
            .and_then(|p| p.get("audience"))
            .and_then(|a| a.as_str())
            .map(Audience::parse)
            .unwrap_or(Audience::Gated),
        bypass_traverse: m
            .get("security")
            .and_then(|s| s.get("bypass_traverse"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false),
        deny_unresolved: m
            .get("security")
            .and_then(|s| s.get("deny_unresolved"))
            .and_then(|b| b.as_bool())
            .unwrap_or(true),
    }
}

#[test]
fn acl_evaluation() {
    let doc = load("cases/acl/evaluation.yaml");
    let p = doc.get("principals").expect("corpus declares principals");

    let users: Vec<User> = p
        .get("users")
        .and_then(|u| u.as_sequence())
        .map(|seq| {
            seq.iter()
                .map(|u| User {
                    id: s(u, "id").unwrap(),
                    display: s(u, "display"),
                    status: s(u, "status"),
                    expires: s(u, "expires"),
                })
                .collect()
        })
        .unwrap_or_default();
    let groups: Vec<Group> = p
        .get("groups")
        .and_then(|g| g.as_sequence())
        .map(|seq| {
            seq.iter()
                .map(|g| Group {
                    id: s(g, "id").unwrap(),
                    display: s(g, "display"),
                    members: list(g, "members"),
                })
                .collect()
        })
        .unwrap_or_default();
    let roles: BTreeMap<String, Vec<String>> = p
        .get("roles")
        .and_then(|r| r.as_mapping())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| {
                    Some((
                        k.as_str()?.to_string(),
                        v.as_sequence()?
                            .iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let principals = Principals::new(users, groups, roles);
    let defaults = doc.get("defaults");
    let mut r = Report::default();

    for c in cases(&doc) {
        let name = s(&c, "name").unwrap();
        let store = build_store(c.get("descriptors"));
        let opts = opts_for(defaults, &c);

        // A case carries either one `request` or a list of `requests`.
        let requests: Vec<Yaml> = match c.get("requests").and_then(|x| x.as_sequence()) {
            Some(seq) => seq.clone(),
            None => {
                let mut req = c.get("request").cloned().expect("case has a request");
                if let (Yaml::Mapping(m), Some(e)) = (&mut req, c.get("expect")) {
                    m.insert(Yaml::String("expect".into()), e.clone());
                }
                vec![req]
            }
        };

        for req in &requests {
            let principal = s(req, "principal").unwrap();
            let path = s(req, "path").unwrap();
            let rights = list(req, "rights");
            let rights_ref: Vec<&str> = rights.iter().map(String::as_str).collect();
            let result = check_access(&store, &principals, &principal, &path, &rights, opts);

            let Some(Yaml::Mapping(expect)) = req.get("expect") else {
                continue;
            };
            for (right, want) in expect {
                let right = right.as_str().unwrap_or_default();
                let tag = format!("{name} [{principal} {right} {path}]");
                let Some(got) = result.decisions.get(right) else {
                    r.check(&tag, "decision present", "missing", "present");
                    continue;
                };
                r.check(
                    &tag,
                    "decision",
                    got.decision.as_str(),
                    s(want, "decision").unwrap(),
                );
                // §14.2: the deciding ACE, not merely the outcome.
                r.check(&tag, "decided by", got.by.clone(), s(want, "by").unwrap());
                if present(want, "failed_at") {
                    r.check(
                        &tag,
                        "failed_at",
                        got.failed_at.clone(),
                        opt_s(want, "failed_at"),
                    );
                }
            }
            let _ = rights_ref;
        }

        if let Some(overall) = s(&c, "overall") {
            // Only meaningful for the single-request form.
            let req = &requests[0];
            let rights = list(req, "rights");
            let result = check_access(
                &store,
                &principals,
                &s(req, "principal").unwrap(),
                &s(req, "path").unwrap(),
                &rights,
                opts,
            );
            r.check(&name, "overall", result.allowed, overall == "allow");
        }

        // Integrity expectations: cycles and unresolved subjects (§7.2, §8.4).
        for want in c
            .get("integrity")
            .and_then(|i| i.as_sequence())
            .unwrap_or(&vec![])
        {
            let code = s(want, "code").unwrap_or_default();
            if code == "GROUP_CYCLE" {
                let subject = s(want, "subject").unwrap_or_default();
                r.check(
                    &name,
                    "GROUP_CYCLE reported",
                    principals
                        .integrity
                        .iter()
                        .any(|i| i.code == "GROUP_CYCLE" && i.subject == subject),
                    true,
                );
            }
            if code == "UNRESOLVED_SUBJECT" {
                // Reported at index time by walking every stored descriptor;
                // here the case's own descriptors stand in for that walk.
                let subject = s(want, "subject").unwrap_or_default();
                let found = store
                    .folder_acls
                    .values()
                    .filter_map(|a| a.folder.as_ref())
                    .chain(store.inline_acls.values())
                    .flat_map(|d| d.dacl.iter())
                    .any(|ace| ace.subject == subject && !principals.exists(&ace.subject));
                r.check(&name, "UNRESOLVED_SUBJECT detectable", found, true);
            }
        }
    }
    r.finish("acl/evaluation");
}

/// §7.2: a membership cycle must terminate and yield the reachable set, never
/// hang or overflow. Asserted directly as well as through the corpus, because
/// a stack overflow in `groups_of` would abort the process rather than fail a
/// case.
#[test]
fn group_cycle_terminates() {
    let groups = vec![
        Group {
            id: "g:a".into(),
            display: None,
            members: vec!["g:b".into()],
        },
        Group {
            id: "g:b".into(),
            display: None,
            members: vec!["g:a".into(), "u:x".into()],
        },
    ];
    let users = vec![User {
        id: "u:x".into(),
        display: None,
        status: Some("active".into()),
        expires: None,
    }];
    let p = Principals::new(users, groups, BTreeMap::new());
    let reachable = p.groups_of("u:x");
    assert!(reachable.contains("g:a") && reachable.contains("g:b"));
    assert!(p.integrity.iter().any(|i| i.code == "GROUP_CYCLE"));
}

/// §7.1 leaves a suspended user's *reported decider* implementation-dependent,
/// which §14.2 requires to match.
///
/// §7.1: "A suspended or expired user MUST be treated as resolving to **no
/// groups and no allows**, while still matching ACEs that name it directly for
/// Deny." Read literally, "name it directly" excludes an `everyone` deny — so
/// `everyone` would leave the subject set along with the groups, and a right
/// covered only by an `everyone` deny would come back `deny` by `default`.
///
/// This implementation (and the TypeScript reference) keep `everyone` in the
/// set and report `deny:everyone`. Both reach `deny`; they disagree about which
/// ACE said so, and §14.2 is explicit that the deciding ACE is part of the
/// assertion because "two implementations can agree on 'denied' for different
/// reasons and only one of them is following §8.4".
///
/// The corpus's one suspended case does not discriminate: on
/// `Notes/Other.md` an explicit `O3` deny naming `u:gone` directly is ordered
/// first, so the `everyone` allow beside it is never consulted either way.
///
/// Keeping `everyone` is the better reading on the merits — §7.1's own
/// justification is that "suspending an account must never widen access", and
/// dropping `everyone` discards a deny that applied a moment earlier — but the
/// text says "directly", so this is pinned here rather than assumed.
#[test]
fn suspended_user_decider_is_underspecified() {
    use basalt::acl::{Decision, EvalOpts};

    let users = vec![User {
        id: "u:gone".into(),
        display: None,
        status: Some("suspended".into()),
        expires: None,
    }];
    let principals = Principals::new(users, Vec::new(), BTreeMap::new());

    let descriptors: Yaml = serde_yaml_ng::from_str(
        "Notes/Any.md:\n  dacl:\n    - {id: X1, type: deny, subject: everyone, rights: [read], flags: []}\n",
    )
    .unwrap();
    let store = build_store(Some(&descriptors));

    let r = check_access(
        &store,
        &principals,
        "u:gone",
        "Notes/Any.md",
        &["read".to_string()],
        EvalOpts {
            bypass_traverse: true,
            ..Default::default()
        },
    );
    assert_eq!(r.decisions["read"].decision, Decision::Deny);
    assert_eq!(
        r.decisions["read"].by, "X1",
        "an `everyone` deny still bites a suspended user, so it is the decider"
    );

    // And the other half of §7.1 that is not in doubt: the allows are gone.
    let descriptors: Yaml = serde_yaml_ng::from_str(
        "Notes/Any.md:\n  dacl:\n    - {id: Y1, type: allow, subject: everyone, rights: [read], flags: []}\n",
    )
    .unwrap();
    let store = build_store(Some(&descriptors));
    let r = check_access(
        &store,
        &principals,
        "u:gone",
        "Notes/Any.md",
        &["read".to_string()],
        EvalOpts {
            bypass_traverse: true,
            ..Default::default()
        },
    );
    assert_eq!(r.decisions["read"].decision, Decision::Deny);
    assert_eq!(
        r.decisions["read"].by, "default",
        "a suspended user's allows vanish, so no ACE decides it"
    );
}
