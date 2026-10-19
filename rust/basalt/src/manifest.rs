//! The manifest, PROTOCOL §3.1.
//!
//! `basalt.yaml` is the only key whose location is fixed, and §15 is blunt
//! about what that means: `security.bypass_traverse` and `publish.audience`
//! change enforcement globally and live in a file inside the vault, so `write`
//! on the manifest is equivalent to `write_acl` everywhere.

use crate::acl::Audience;
use crate::frontmatter::yaml_text;
use serde_yaml_ng::Value as Yaml;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalePolicy {
    Rebuild,
    ServeStale,
    Refuse,
}

impl StalePolicy {
    pub fn parse(s: &str) -> Self {
        match s {
            "serve-stale" => Self::ServeStale,
            "refuse" => Self::Refuse,
            _ => Self::Rebuild,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rebuild => "rebuild",
            Self::ServeStale => "serve-stale",
            Self::Refuse => "refuse",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Manifest {
    /// The spec major version. A reader MUST refuse a vault whose value it
    /// does not implement, and MUST tolerate unknown keys within a version it
    /// does (§3.1, §16).
    pub basalt: i64,
    pub vault_id: String,
    pub vault_title: Option<String>,
    pub created: Option<String>,
    pub default_locale: Option<String>,
    pub capabilities: Vec<String>,
    pub audience: Audience,
    pub home: Option<String>,
    pub theme: Option<String>,
    pub stale_policy: StalePolicy,
    pub bypass_traverse: bool,
    pub anonymous_principal: String,
    pub deny_unresolved: bool,
    pub redact_titles: bool,
    /// The interop profiles this vault declares (§17, INTEROP §10).
    ///
    /// Present, it is a ceiling in the same shape as the §12.2 audience
    /// ceiling: a gatekeeper MUST NOT mount a surface the vault does not
    /// list. Absent — an empty vector here — the vault makes no claim, since
    /// a vault written before the annex says nothing about profiles, and the
    /// operator decides what to mount.
    pub interop: Option<Vec<String>>,
}

impl Manifest {
    pub fn from_yaml(v: &Yaml) -> Result<Self, String> {
        let basalt = v
            .get("basalt")
            .and_then(|b| b.as_i64())
            .ok_or_else(|| "basalt.yaml: `basalt` must be an integer".to_string())?;
        if basalt != crate::indexer::SPEC {
            return Err(format!("unsupported spec version: basalt={basalt}"));
        }
        let vault = v.get("vault");
        let vault_id = vault
            .and_then(|x| x.get("id"))
            .and_then(yaml_text)
            .ok_or_else(|| "basalt.yaml: `vault.id` is required".to_string())?;

        let publish = v.get("publish");
        let security = v.get("security");
        let index = v.get("index");

        Ok(Self {
            basalt,
            vault_id,
            vault_title: vault.and_then(|x| x.get("title")).and_then(yaml_text),
            created: vault.and_then(|x| x.get("created")).and_then(yaml_text),
            default_locale: vault
                .and_then(|x| x.get("default_locale"))
                .and_then(yaml_text),
            capabilities: v
                .get("transport")
                .and_then(|t| t.get("capabilities"))
                .and_then(|c| c.as_sequence())
                .map(|s| s.iter().filter_map(yaml_text).collect())
                .unwrap_or_default(),
            audience: publish
                .and_then(|p| p.get("audience"))
                .and_then(yaml_text)
                .map(|s| Audience::parse(&s))
                .unwrap_or(Audience::Gated),
            home: publish.and_then(|p| p.get("home")).and_then(yaml_text),
            theme: publish.and_then(|p| p.get("theme")).and_then(yaml_text),
            stale_policy: index
                .and_then(|i| i.get("stale_policy"))
                .and_then(yaml_text)
                .map(|s| StalePolicy::parse(&s))
                .unwrap_or(StalePolicy::Rebuild),
            // §8.5 is explicit that the full traverse chain is required unless
            // the vault opts out, so the default here is the strict one.
            bypass_traverse: security
                .and_then(|s| s.get("bypass_traverse"))
                .and_then(|b| b.as_bool())
                .unwrap_or(false),
            anonymous_principal: security
                .and_then(|s| s.get("anonymous_principal"))
                .and_then(yaml_text)
                .unwrap_or_else(|| "anonymous".to_string()),
            // §15: MUST NOT be inverted for convenience — the alternative
            // makes a deleted group silently widen access.
            deny_unresolved: security
                .and_then(|s| s.get("deny_unresolved"))
                .and_then(|b| b.as_bool())
                .unwrap_or(true),
            redact_titles: security
                .and_then(|s| s.get("redact_titles"))
                .and_then(|b| b.as_bool())
                .unwrap_or(true),
            // None and Some(vec![]) are different answers: the first is "this
            // vault says nothing", the second is "this vault serves none".
            interop: publish
                .and_then(|p| p.get("interop"))
                .and_then(|i| i.as_sequence())
                .map(|seq| seq.iter().filter_map(yaml_text).collect()),
        })
    }

    pub fn eval_opts(&self) -> crate::acl::EvalOpts {
        crate::acl::EvalOpts {
            audience: self.audience,
            bypass_traverse: self.bypass_traverse,
            deny_unresolved: self.deny_unresolved,
        }
    }
}
