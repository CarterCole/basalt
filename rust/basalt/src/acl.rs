//! Principals and NTFS-style access control, PROTOCOL §7 and §8.
//!
//! The band ordering in §8.4 step 4 is the whole of this module's difficulty.
//! An explicit allow on a note **does** override an inherited deny from its
//! folder: that is NTFS behavior, it is what makes "deny the whole tree, allow
//! this one file" expressible, and an implementation that globally prioritizes
//! deny over allow is not conforming.

use crate::frontmatter::{yaml_text, Severity};
use serde_yaml_ng::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Every right (§8.1). `full_control` expands to exactly this list.
pub const RIGHTS: [&str; 13] = [
    "read",
    "list",
    "traverse",
    "comment",
    "write",
    "create_child",
    "delete",
    "delete_child",
    "read_acl",
    "write_acl",
    "take_ownership",
    "read_history",
    "publish",
];

/// The well-known principals of §7.3. A vault MUST NOT define a user or group
/// with any of these ids.
pub const WELL_KNOWN: [&str; 5] = ["everyone", "anonymous", "authenticated", "owner", "system"];

/// The five predefined roles of §7.4. A vault MAY override any of them.
pub fn default_roles() -> BTreeMap<String, Vec<String>> {
    let mut m = BTreeMap::new();
    let put = |m: &mut BTreeMap<String, Vec<String>>, k: &str, v: &[&str]| {
        m.insert(k.to_string(), v.iter().map(|s| s.to_string()).collect());
    };
    put(&mut m, "reader", &["read", "list", "traverse"]);
    put(
        &mut m,
        "commenter",
        &["read", "list", "traverse", "comment"],
    );
    put(
        &mut m,
        "editor",
        &[
            "read",
            "list",
            "traverse",
            "comment",
            "write",
            "create_child",
            "delete_child",
        ],
    );
    put(&mut m, "owner", &["full_control"]);
    put(
        &mut m,
        "auditor",
        &["read", "list", "traverse", "read_acl", "read_history"],
    );
    m
}

/// The inheritance flags of §8.3, taken from NTFS with the same meanings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Flag {
    /// `oi` — object inherit: applies to non-folder descendants.
    ObjectInherit,
    /// `ci` — container inherit: applies to folder descendants.
    ContainerInherit,
    /// `np` — no-propagate: applies to direct children only, then stops.
    NoPropagate,
    /// `io` — inherit-only: does not apply to the object carrying it.
    InheritOnly,
}

impl Flag {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "oi" => Some(Self::ObjectInherit),
            "ci" => Some(Self::ContainerInherit),
            "np" => Some(Self::NoPropagate),
            "io" => Some(Self::InheritOnly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceType {
    Allow,
    Deny,
}

/// An access control entry (§8.2).
#[derive(Debug, Clone)]
pub struct Ace {
    pub ace_type: AceType,
    pub subject: String,
    /// As authored: may name individual rights, roles, or `full_control`.
    /// Roles are expanded at evaluation time, never baked in (§7.4).
    pub rights: Vec<String>,
    pub flags: BTreeSet<Flag>,
    /// A fixture-only identifier, so a conformance case can assert *which*
    /// ACE decided a right. §14.2 requires that: two implementations can agree
    /// on "denied" for different reasons and only one is following §8.4.
    pub id: Option<String>,
}

impl Ace {
    pub fn from_yaml(v: &Yaml) -> Option<Self> {
        let ace_type = match v.get("type").and_then(yaml_text).as_deref() {
            Some("deny") => AceType::Deny,
            // §8.2 lists `allow | deny`; anything else is read as allow so a
            // typo cannot silently become a deny, which would be the more
            // surprising failure.
            _ => AceType::Allow,
        };
        let subject = v.get("subject").and_then(yaml_text)?;
        let rights = v
            .get("rights")
            .and_then(|r| r.as_sequence())
            .map(|s| s.iter().filter_map(yaml_text).collect())
            .unwrap_or_default();
        let flags = v
            .get("flags")
            .and_then(|f| f.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(yaml_text)
                    .filter_map(|f| Flag::parse(&f))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            ace_type,
            subject,
            rights,
            flags,
            id: v.get("id").and_then(yaml_text),
        })
    }

    /// The label a decision reports. The fixture `id` when present, otherwise
    /// a readable `type:subject`.
    pub fn label(&self) -> String {
        self.id.clone().unwrap_or_else(|| {
            format!(
                "{}:{}",
                match self.ace_type {
                    AceType::Allow => "allow",
                    AceType::Deny => "deny",
                },
                self.subject
            )
        })
    }
}

/// A security descriptor (§8.6): an owner, the inheritance-blocking flag, and
/// an ordered DACL.
#[derive(Debug, Clone, Default)]
pub struct Descriptor {
    pub owner: Option<String>,
    /// §8.3: block inheritance from ancestors — the NTFS "disable
    /// inheritance" case. A protected folder SHOULD carry its own complete
    /// descriptor, since otherwise it denies everything to everyone, which is
    /// valid but rarely intended.
    pub protected: bool,
    pub dacl: Vec<Ace>,
}

impl Descriptor {
    pub fn from_yaml(v: &Yaml) -> Self {
        Self {
            owner: v.get("owner").and_then(yaml_text),
            protected: v
                .get("protected")
                .and_then(|p| p.as_bool())
                .unwrap_or(false),
            dacl: v
                .get("dacl")
                .and_then(|d| d.as_sequence())
                .map(|s| s.iter().filter_map(Ace::from_yaml).collect())
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub display: Option<String>,
    pub status: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id: String,
    pub display: Option<String>,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityNote {
    pub severity: Severity,
    pub code: String,
    pub subject: String,
}

/// The principal directory: users, groups and roles, with transitive
/// membership (§7).
pub struct Principals {
    pub users: BTreeMap<String, User>,
    pub groups: BTreeMap<String, Group>,
    pub roles: BTreeMap<String, Vec<String>>,
    pub integrity: Vec<IntegrityNote>,
    /// `now` as an RFC 3339 string, for user expiry. Injected rather than
    /// read from the clock so that an evaluation is reproducible.
    now: String,
    groups_cache: std::sync::Mutex<HashMap<String, BTreeSet<String>>>,
}

impl Principals {
    pub fn new(users: Vec<User>, groups: Vec<Group>, roles: BTreeMap<String, Vec<String>>) -> Self {
        let mut all_roles = default_roles();
        all_roles.extend(roles);

        let mut p = Self {
            users: users.into_iter().map(|u| (u.id.clone(), u)).collect(),
            groups: groups.into_iter().map(|g| (g.id.clone(), g)).collect(),
            roles: all_roles,
            integrity: Vec::new(),
            now: crate::transport::fs::now_rfc3339(),
            groups_cache: std::sync::Mutex::new(HashMap::new()),
        };
        p.validate();
        p
    }

    pub fn empty() -> Self {
        Self::new(Vec::new(), Vec::new(), BTreeMap::new())
    }

    fn validate(&mut self) {
        for id in self.users.keys().chain(self.groups.keys()) {
            if WELL_KNOWN.contains(&id.as_str()) {
                self.integrity.push(IntegrityNote {
                    severity: Severity::Error,
                    code: "RESERVED_PRINCIPAL_ID".into(),
                    subject: id.clone(),
                });
            }
        }
        // §7.2: a membership cycle is an integrity error, and the expansion
        // must still terminate rather than hanging or overflowing. Detected
        // once, up front.
        let cyclic: Vec<String> = self
            .groups
            .keys()
            .filter(|id| self.has_cycle(id, &mut HashSet::new()))
            .cloned()
            .collect();
        for id in cyclic {
            self.integrity.push(IntegrityNote {
                severity: Severity::Error,
                code: "GROUP_CYCLE".into(),
                subject: id,
            });
        }
    }

    fn has_cycle(&self, id: &str, seen: &mut HashSet<String>) -> bool {
        if seen.contains(id) {
            return true;
        }
        let Some(g) = self.groups.get(id) else {
            return false;
        };
        seen.insert(id.to_string());
        for m in &g.members {
            if self.groups.contains_key(m) && self.has_cycle(m, &mut seen.clone()) {
                return true;
            }
        }
        false
    }

    /// True when the id names a known user, group or well-known principal.
    pub fn exists(&self, id: &str) -> bool {
        WELL_KNOWN.contains(&id) || self.users.contains_key(id) || self.groups.contains_key(id)
    }

    /// Is this user active? Suspended and expired both count as inactive
    /// (§7.1), and both lose every allow while keeping every deny.
    pub fn is_active(&self, user_id: &str) -> bool {
        let Some(u) = self.users.get(user_id) else {
            return false;
        };
        if u.status.as_deref().is_some_and(|s| s != "active") {
            return false;
        }
        // RFC 3339 UTC strings compare lexicographically in time order, which
        // is why the protocol asks for that format in the first place.
        if u.expires.as_deref().is_some_and(|e| e <= self.now.as_str()) {
            return false;
        }
        true
    }

    /// Every group reachable from a principal, transitively (§7.2).
    ///
    /// Cycle-safe by construction: the visited set bounds the walk, so a cycle
    /// yields the reachable set and terminates.
    pub fn groups_of(&self, principal_id: &str) -> BTreeSet<String> {
        if let Some(hit) = self.groups_cache.lock().unwrap().get(principal_id) {
            return hit.clone();
        }
        let mut out = BTreeSet::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut stack = vec![principal_id.to_string()];
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            for (gid, g) in &self.groups {
                if g.members.contains(&id) && out.insert(gid.clone()) {
                    stack.push(gid.clone());
                }
            }
        }
        self.groups_cache
            .lock()
            .unwrap()
            .insert(principal_id.to_string(), out.clone());
        out
    }

    /// Expand a rights list, resolving roles and `full_control` (§7.4, §8.1).
    ///
    /// Returns the resolved rights and the names that resolved to nothing — an
    /// ACE naming an undefined role is an integrity error and is treated per
    /// `security.deny_unresolved`.
    pub fn expand_rights(&self, rights: &[String]) -> (BTreeSet<String>, Vec<String>) {
        let mut out = BTreeSet::new();
        let mut unresolved = Vec::new();
        self.expand_into(rights, &mut out, &mut unresolved, &mut HashSet::new());
        (out, unresolved)
    }

    fn expand_into(
        &self,
        rights: &[String],
        out: &mut BTreeSet<String>,
        unresolved: &mut Vec<String>,
        seen_roles: &mut HashSet<String>,
    ) {
        for r in rights {
            if r == "full_control" {
                for x in RIGHTS {
                    out.insert(x.to_string());
                }
            } else if RIGHTS.contains(&r.as_str()) {
                out.insert(r.clone());
            } else if let Some(role) = self.roles.get(r) {
                // A role that names itself would otherwise recurse forever.
                if seen_roles.insert(r.clone()) {
                    self.expand_into(role, out, unresolved, seen_roles);
                }
            } else {
                unresolved.push(r.clone());
            }
        }
    }
}

/// The subject set for a request (§8.4 step 1): the principal, its transitive
/// groups, the applicable well-known principals, and `owner` when it owns the
/// object being tested.
///
/// Computed per object, because `owner` depends on which object is being
/// evaluated — an ancestor's traverse check uses that ancestor's owner.
pub fn subject_set(
    principals: &Principals,
    principal_id: &str,
    owner: Option<&str>,
) -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert(principal_id.to_string());
    s.insert("everyone".to_string());

    if principal_id == "anonymous" {
        s.insert("anonymous".to_string());
    } else if principals.is_active(principal_id) {
        s.insert("authenticated".to_string());
        s.extend(principals.groups_of(principal_id));
    }
    // A suspended or expired user keeps only its own id and `everyone`, so
    // denies naming it still bite while its group-derived allows vanish
    // (§7.1). Denies outlive suspension on purpose: suspending an account
    // must never widen access.

    if owner.is_some_and(|o| o == principal_id) {
        s.insert("owner".to_string());
    }
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// One right's outcome, with the thing that decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RightDecision {
    pub decision: Decision,
    /// An ACE label, or one of the synthetic deciders: `default` (no ACE
    /// mentioned the right), `audience_ceiling` (§12.2), `missing_publish`
    /// (§8.1).
    pub by: String,
    /// The ancestor folder whose traverse check failed (§8.5).
    pub failed_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub decisions: BTreeMap<String, RightDecision>,
    pub allowed: bool,
    pub subjects: Vec<String>,
}

/// One link in the descriptor chain of §8.4 step 2.
#[derive(Debug, Clone)]
pub struct ChainLink {
    pub path: String,
    pub descriptor: Descriptor,
    /// 0 for the object's own descriptor, 1 for its parent folder, and so on.
    pub distance: usize,
}

/// The vault-wide audience ceiling (§12.2). Applies *before* §8.4 and can only
/// narrow, never widen, what the ACL allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    Public,
    Gated,
    Private,
}

impl Audience {
    pub fn parse(s: &str) -> Self {
        match s {
            "public" => Self::Public,
            "private" => Self::Private,
            _ => Self::Gated,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Gated => "gated",
            Self::Private => "private",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EvalOpts {
    pub audience: Audience,
    /// §8.5: the Windows "Bypass traverse checking" analogue. `false` by
    /// default — implementations MUST require the full chain unless the vault
    /// opts out.
    pub bypass_traverse: bool,
    /// §8.4: an unresolvable subject, role or group denies all its rights when
    /// true (the default and the safe direction), or is dropped when false.
    pub deny_unresolved: bool,
}

impl Default for EvalOpts {
    fn default() -> Self {
        Self {
            audience: Audience::Gated,
            bypass_traverse: false,
            deny_unresolved: true,
        }
    }
}

struct Candidate<'a> {
    ace: &'a Ace,
    explicit: bool,
    distance: usize,
    order: usize,
}

/// Evaluate a request against one descriptor chain (§8.4).
///
/// `chain` is ordered nearest-first and already truncated at the first
/// `protected`. This decides one object; the ancestor traverse checks of §8.5
/// are separate evaluations that compose, and live in `security.rs`.
pub fn evaluate_chain(
    principals: &Principals,
    principal_id: &str,
    chain: &[ChainLink],
    rights: &[String],
    target_is_folder: bool,
    opts: EvalOpts,
) -> Outcome {
    let own_owner = chain.first().and_then(|c| c.descriptor.owner.as_deref());
    let subjects = subject_set(principals, principal_id, own_owner);
    let anon = principal_id == "anonymous";

    // §12.2: the ceiling applies before the DACL is consulted at all, so that
    // taking a vault private is one edit rather than an audit of every ACE.
    if anon && opts.audience != Audience::Public {
        let decisions = rights
            .iter()
            .map(|r| {
                (
                    r.clone(),
                    RightDecision {
                        decision: Decision::Deny,
                        by: "audience_ceiling".into(),
                        failed_at: None,
                    },
                )
            })
            .collect();
        return Outcome {
            decisions,
            allowed: false,
            subjects: subjects.into_iter().collect(),
        };
    }

    // §8.4 step 3: flatten to candidates, dropping ACEs that do not apply.
    let mut candidates: Vec<Candidate> = Vec::new();
    for link in chain {
        for (i, ace) in link.descriptor.dacl.iter().enumerate() {
            let explicit = link.distance == 0;
            if explicit {
                // `io` never applies to the object carrying it.
                if ace.flags.contains(&Flag::InheritOnly) {
                    continue;
                }
            } else {
                // An inherited ACE applies only if it carries the flag for
                // this object's kind.
                if target_is_folder && !ace.flags.contains(&Flag::ContainerInherit) {
                    continue;
                }
                if !target_is_folder && !ace.flags.contains(&Flag::ObjectInherit) {
                    continue;
                }
                // `np` stops propagation past direct children.
                if ace.flags.contains(&Flag::NoPropagate) && link.distance > 1 {
                    continue;
                }
            }
            candidates.push(Candidate {
                ace,
                explicit,
                distance: link.distance,
                order: i,
            });
        }
    }

    // §8.4 step 4: four bands — explicit deny, explicit allow, inherited deny,
    // inherited allow — then nearer ancestors first within a band, then the
    // authored order within one descriptor.
    //
    // Deny beats allow only *within* a band. Globally prioritizing deny is the
    // classic non-conforming shortcut.
    let band = |c: &Candidate| -> u8 {
        (if c.explicit { 0u8 } else { 2u8 }) + u8::from(c.ace.ace_type == AceType::Allow)
    };
    candidates.sort_by_key(|c| (band(c), c.distance, c.order));

    // §8.4 step 5: resolve each right independently. One ACE list can allow
    // `read` and deny `write` for the same subject in one pass.
    let mut decisions = BTreeMap::new();
    let mut ceiling_dropped: BTreeSet<String> = BTreeSet::new();

    for r in rights {
        let mut decided: Option<RightDecision> = None;
        for c in &candidates {
            let ace = c.ace;

            if !principals.exists(&ace.subject) {
                // §8.4: an unresolvable subject denies its rights when
                // deny_unresolved is true. A typo in a group name must not
                // silently grant access.
                let (ar, _) = principals.expand_rights(&ace.rights);
                if opts.deny_unresolved && ar.contains(r) {
                    decided = Some(RightDecision {
                        decision: Decision::Deny,
                        by: ace
                            .id
                            .clone()
                            .unwrap_or_else(|| "unresolved_subject".into()),
                        failed_at: None,
                    });
                    break;
                }
                continue;
            }
            if !subjects.contains(&ace.subject) {
                continue;
            }

            // §12.2: under `private`, grants to `everyone` are ignored. The
            // right is remembered so the denial can name the ceiling rather
            // than looking like a vault with no ACL at all.
            if opts.audience == Audience::Private
                && ace.subject == "everyone"
                && ace.ace_type == AceType::Allow
            {
                let (ar, _) = principals.expand_rights(&ace.rights);
                if ar.contains(r) {
                    ceiling_dropped.insert(r.clone());
                }
                continue;
            }

            // §7.1: a suspended user loses its allows but keeps its denies.
            if ace.ace_type == AceType::Allow
                && !anon
                && principals.users.contains_key(principal_id)
                && !principals.is_active(principal_id)
            {
                continue;
            }

            let (ace_rights, _) = principals.expand_rights(&ace.rights);
            if !ace_rights.contains(r) {
                continue;
            }

            decided = Some(RightDecision {
                decision: match ace.ace_type {
                    AceType::Deny => Decision::Deny,
                    AceType::Allow => Decision::Allow,
                },
                by: ace.label(),
                failed_at: None,
            });
            break; // the first ACE mentioning this right decides it
        }

        decisions.insert(
            r.clone(),
            decided.unwrap_or_else(|| RightDecision {
                decision: Decision::Deny,
                by: if ceiling_dropped.contains(r) {
                    "audience_ceiling".into()
                } else {
                    // §8.4 step 5: a right no ACE mentions is denied.
                    "default".into()
                },
                failed_at: None,
            }),
        );
    }

    // §8.1: `anonymous` needs `publish` in addition to `read`, so that "shared
    // with everyone who has an account" and "on the public internet" stay
    // different decisions and no single mis-set ACE can confuse them.
    if anon
        && decisions
            .get("read")
            .is_some_and(|d| d.decision == Decision::Allow)
    {
        let pub_outcome = evaluate_chain(
            principals,
            principal_id,
            chain,
            &["publish".to_string()],
            target_is_folder,
            EvalOpts {
                audience: Audience::Public,
                ..opts
            },
        );
        if pub_outcome.decisions["publish"].decision != Decision::Allow {
            decisions.insert(
                "read".into(),
                RightDecision {
                    decision: Decision::Deny,
                    by: "missing_publish".into(),
                    failed_at: None,
                },
            );
        }
    }

    // §8.4 step 6: the request succeeds only if every right resolved to allow.
    let allowed = rights
        .iter()
        .all(|r| decisions[r].decision == Decision::Allow);

    Outcome {
        decisions,
        allowed,
        subjects: subjects.into_iter().collect(),
    }
}
