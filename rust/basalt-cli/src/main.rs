//! The basalt CLI.
//!
//! `basalt check` is the self-check PROTOCOL §14.3 *requires* of a conforming
//! implementation, not an optional nicety: it is the tool a vault owner runs
//! to answer "is my private note actually private", and without it the answer
//! is unknowable.

use basalt::acl::RIGHTS;
use basalt::canonical::Json;
use basalt::frontmatter::Severity;
use basalt::transport::{FsTransport, Transport};
use basalt::vault::{IndexState, Vault, INDEX_KEYS};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
basalt — a Rust implementation of the Basalt Protocol v1 (conformance L0-L4)

  basalt check    [--vault DIR | --bucket B] [--principal ID] [--path P]
                  Self-check (§14.3): integrity, index freshness, whether a
                  rebuild reproduces the stored indexes byte for byte, and the
                  ACL evaluation of a principal against a path.

  basalt index    [--vault DIR | --bucket B] [--write] [--force]
                  Rebuild every index from content alone. --write persists.
                  §10.7 refuses to replace a non-empty stored index with an
                  empty one; --force overrides that, and almost never should.

  basalt mint     [--vault DIR | --bucket B]
                  Mint node ids for unbound objects (§4.3).

  basalt serve    [--vault DIR | --bucket B] [--port N] [--principal ID]
                  Run the gatekeeper (§12). --principal forces an identity for
                  local testing; without it every request is anonymous.

  basalt effective --path P [--principal ID]
                  Effective rights with the deciding ACE per right (§8.7).

  basalt tree     [--principal ID]
                  The visible tree for a principal.

  basalt export   [--vault DIR] --out DIR [--vault-id ULID]
                  Export the public subset as a complete, servable vault
                  (§12.6): only nodes granting read and publish to anonymous,
                  with every index regenerated rather than copied (§8.8).

  basalt digest   Print the merkle root over content/ (§10.6).

Transports:
  --vault DIR                        a local folder (the default: .)
  --bucket NAME [--prefix P/]        an S3-compatible store, with
    [--endpoint URL] [--region R]    --flavor s3|minio|r2
";

struct Args {
    cmd: String,
    flags: BTreeMap<String, String>,
    bare: Vec<String>,
}

impl Args {
    fn parse() -> Self {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        let mut flags = BTreeMap::new();
        let mut bare = Vec::new();
        let mut i = 0;
        let cmd = argv.first().cloned().unwrap_or_default();
        if !argv.is_empty() {
            i = 1;
        }
        while i < argv.len() {
            if let Some(name) = argv[i].strip_prefix("--") {
                let next = argv.get(i + 1);
                match next {
                    Some(v) if !v.starts_with("--") => {
                        flags.insert(name.to_string(), v.clone());
                        i += 2;
                    }
                    _ => {
                        flags.insert(name.to_string(), "true".into());
                        i += 1;
                    }
                }
            } else {
                bare.push(argv[i].clone());
                i += 1;
            }
        }
        Self { cmd, flags, bare }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(String::as_str)
    }

    fn or(&self, name: &str, fallback: &str) -> String {
        self.get(name).unwrap_or(fallback).to_string()
    }

    fn on(&self, name: &str) -> bool {
        self.get(name) == Some("true")
    }
}

mod paint {
    use std::sync::OnceLock;
    fn enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| std::env::var_os("NO_COLOR").is_none())
    }
    fn wrap(code: &str, s: &str) -> String {
        if enabled() {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub fn dim(s: &str) -> String {
        wrap("2", s)
    }
    pub fn bold(s: &str) -> String {
        wrap("1", s)
    }
    pub fn red(s: &str) -> String {
        wrap("31", s)
    }
    pub fn yellow(s: &str) -> String {
        wrap("33", s)
    }
    pub fn green(s: &str) -> String {
        wrap("32", s)
    }
}

fn transport(args: &Args) -> Result<Box<dyn Transport>, String> {
    if let Some(bucket) = args.get("bucket") {
        #[cfg(feature = "s3")]
        {
            use basalt::transport::{S3Config, S3Flavor, S3Transport};
            let cfg = S3Config {
                bucket: bucket.to_string(),
                prefix: args.or("prefix", ""),
                endpoint: args.get("endpoint").map(str::to_string),
                region: args.get("region").map(str::to_string),
                flavor: Some(S3Flavor::parse(&args.or("flavor", "s3"))),
                force_path_style: None,
            };
            return S3Transport::new(cfg)
                .map(|t| Box::new(t) as Box<dyn Transport>)
                .map_err(|e| e.to_string());
        }
        #[cfg(not(feature = "s3"))]
        {
            let _ = bucket;
            return Err(
                "this build has no S3 support; rebuild with --features s3, or use --vault"
                    .to_string(),
            );
        }
    }
    let dir = PathBuf::from(args.or("vault", "."));
    Ok(Box::new(FsTransport::new(dir)))
}

fn open(args: &Args) -> Result<Vault, String> {
    Vault::open(transport(args)?).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}: {e}", paint::red("error"));
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> Result<ExitCode, String> {
    match args.cmd.as_str() {
        "check" => check(args),
        "index" => {
            use basalt::vault::IndexWrite;
            let mut v = open(args)?;
            let write = match (args.on("write"), args.on("force")) {
                (false, _) => IndexWrite::dry(),
                (true, false) => IndexWrite::persist(),
                (true, true) => IndexWrite::forced(),
            };
            v.reindex_opts(write).map_err(|e| e.to_string())?;
            let ix = v.indexes.as_ref().unwrap();
            for (name, key) in INDEX_KEYS {
                let bytes = ix.by_name(name).map(|o| o.to_canonical_bytes().len());
                println!(
                    "{:<24} {}",
                    key,
                    paint::dim(&format!("{} bytes", bytes.unwrap_or(0)))
                );
            }
            println!(
                "\n{} {}",
                if args.on("write") {
                    paint::green("written")
                } else {
                    paint::dim("not written (pass --write)")
                },
                paint::dim(&format!("source_digest {}", ix.source_digest))
            );
            Ok(ExitCode::SUCCESS)
        }
        "mint" => {
            let mut v = open(args)?;
            let minted = v.mint_ids().map_err(|e| e.to_string())?;
            if minted.is_empty() {
                println!("{}", paint::dim("no unbound objects"));
            }
            for (path, id) in &minted {
                println!("{} {}", paint::green(id), path);
            }
            Ok(ExitCode::SUCCESS)
        }
        "export" => {
            use basalt::vault::ExportOpts;
            let out = args
                .get("out")
                .or_else(|| args.bare.first().map(String::as_str))
                .ok_or("export: --out DIR is required")?;
            let mut v = open(args)?;
            v.reindex(false).map_err(|e| e.to_string())?;
            let dest = Box::new(FsTransport::new(PathBuf::from(out)));
            let (summary, _) = v
                .export(
                    dest,
                    ExportOpts {
                        vault_id: args.get("vault-id").map(str::to_string),
                    },
                )
                .map_err(|e| e.to_string())?;
            println!(
                "{} {}",
                paint::bold(&format!("exported to {out}")),
                paint::dim(&format!("vault {}", summary.vault_id))
            );
            for p in &summary.included {
                println!("  {} {p}", paint::green("public "));
            }
            for p in &summary.excluded {
                println!("  {} {p}", paint::dim("omitted"));
            }
            println!(
                "\n{}",
                paint::dim(&format!(
                    "{} published, {} omitted, digest {}",
                    summary.included.len(),
                    summary.excluded.len(),
                    summary.source_digest
                ))
            );
            Ok(ExitCode::SUCCESS)
        }
        "digest" => {
            let v = open(args)?;
            let (state, current, stored) = v.index_state().map_err(|e| e.to_string())?;
            println!("{current}");
            println!(
                "{}",
                paint::dim(&format!(
                    "state={} stored={}",
                    state.as_str(),
                    stored.as_deref().unwrap_or("<none>")
                ))
            );
            Ok(ExitCode::SUCCESS)
        }
        "effective" => {
            let mut v = open(args)?;
            v.reindex(false).map_err(|e| e.to_string())?;
            let who = args.or("principal", "anonymous");
            let path = args
                .get("path")
                .or_else(|| args.bare.first().map(String::as_str))
                .ok_or("effective: --path is required")?;
            let e = v.effective(&who, path);
            println!(
                "{} {} {}",
                paint::bold(&who),
                paint::dim("on"),
                paint::bold(path)
            );
            for r in RIGHTS {
                let d = &e.decisions[r];
                let mark = match d.decision {
                    basalt::acl::Decision::Allow => paint::green("allow"),
                    basalt::acl::Decision::Deny => paint::red("deny "),
                };
                let at = d
                    .failed_at
                    .as_deref()
                    .map(|f| {
                        // The vault root is the empty folder path; spelling it
                        // "/" keeps the message readable.
                        format!(
                            " (traverse failed at {})",
                            if f.is_empty() { "/" } else { f }
                        )
                    })
                    .unwrap_or_default();
                println!("  {mark} {:<16} {}{at}", r, paint::dim(&d.by));
            }
            Ok(ExitCode::SUCCESS)
        }
        "tree" => {
            let mut v = open(args)?;
            v.reindex(false).map_err(|e| e.to_string())?;
            let who = args.or("principal", "anonymous");
            match v.tree(&who) {
                None => {
                    println!("{}", paint::dim("(nothing visible)"));
                }
                Some(t) => print_tree(&t, 0),
            }
            Ok(ExitCode::SUCCESS)
        }
        "serve" => {
            use basalt::gatekeeper::Gatekeeper;
            use std::sync::Arc;
            let mut v = open(args)?;
            let state = v.ensure_indexes().map_err(|e| e.to_string())?;
            let vault_id = v.manifest.vault_id.clone();
            let mut gk = Gatekeeper::new(v);
            if let Some(who) = args.get("principal") {
                // Local testing only: §12.1 forbids letting a client assert
                // its own principal id, so a real deployment supplies an
                // `identify` that reads a trusted session instead.
                gk = gk.with_fixed_principal(who);
            }
            gk.set_index_state(state);
            let addr = format!("127.0.0.1:{}", args.or("port", "4380"));
            println!(
                "{} {} {}",
                paint::bold("gatekeeper"),
                paint::dim(&format!("vault {vault_id}")),
                paint::dim(&format!("index {}", state.as_str()))
            );
            println!("  http://{addr}/api/v1/manifest");
            Arc::new(gk).listen(&addr).map_err(|e| e.to_string())?;
            Ok(ExitCode::SUCCESS)
        }
        "" | "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

fn print_tree(t: &basalt::vault::TreeNode, depth: usize) {
    let pad = "  ".repeat(depth);
    let label = t.title.as_deref().unwrap_or("/");
    println!("{pad}{}/", paint::bold(label));
    for e in &t.entries {
        println!(
            "{pad}  {} {}",
            basalt::keys::basename(&e.path),
            paint::dim(&format!("({})", e.kind))
        );
    }
    for f in &t.folders {
        print_tree(f, depth + 1);
    }
}

/// The four things §14.3 requires a self-check to report.
fn check(args: &Args) -> Result<ExitCode, String> {
    let mut v = open(args)?;

    // Read what is stored *before* rebuilding, so the comparison is honest.
    let stored = v.load_stored_indexes().map_err(|e| e.to_string())?;
    v.reindex(false).map_err(|e| e.to_string())?;

    println!(
        "{} {}",
        paint::bold(&format!("vault {}", v.manifest.vault_id)),
        paint::dim(v.manifest.vault_title.as_deref().unwrap_or(""))
    );
    println!(
        "{}",
        paint::dim(&format!(
            "audience={} bypass_traverse={} deny_unresolved={} stale_policy={}",
            v.manifest.audience.as_str(),
            v.manifest.bypass_traverse,
            v.manifest.deny_unresolved,
            v.manifest.stale_policy.as_str()
        ))
    );

    let mut failed = false;

    // 1. Integrity (§10.7).
    let issues = v.integrity();
    let errors = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .count();
    let warnings = issues.len() - errors;
    println!(
        "\n{}  {}, {}",
        paint::bold("integrity"),
        if errors > 0 {
            paint::red(&format!("{errors} error(s)"))
        } else {
            paint::green("0 errors")
        },
        if warnings > 0 {
            paint::yellow(&format!("{warnings} warning(s)"))
        } else {
            "0 warnings".to_string()
        }
    );
    for i in issues.iter().take(20) {
        let tag = if i.severity == Severity::Error {
            paint::red("error")
        } else {
            paint::yellow("warn ")
        };
        println!(
            "  {tag} {:<24} {} {}",
            i.code,
            paint::dim(i.path.as_deref().unwrap_or("")),
            i.detail.as_deref().unwrap_or("")
        );
    }
    if issues.len() > 20 {
        println!("{}", paint::dim(&format!("  …{} more", issues.len() - 20)));
    }
    if errors > 0 {
        failed = true;
    }

    // 2. Freshness (§10.6) — one digest comparison, never timestamps.
    let current = v.indexes.as_ref().unwrap().source_digest.clone();
    let stored_digest = stored
        .get("nodes")
        .and_then(|n| n.get("source_digest"))
        .and_then(|d| d.as_str())
        .map(str::to_string);
    let state = match &stored_digest {
        None => IndexState::Stale,
        Some(s) if *s == current => IndexState::Fresh,
        Some(_) => IndexState::Stale,
    };
    println!(
        "\n{}      {}",
        paint::bold("index"),
        match (&stored_digest, state) {
            (None, _) => paint::yellow("no stored index"),
            (_, IndexState::Fresh) => paint::green("fresh"),
            _ => paint::yellow("stale"),
        }
    );
    println!("{}", paint::dim(&format!("  current {current}")));
    if let Some(s) = &stored_digest {
        println!("{}", paint::dim(&format!("  stored  {s}")));
    }

    // 3. Byte-for-byte reproduction (§13).
    println!("\n{}", paint::bold("reproduction"));
    if stored.is_empty() {
        println!("{}", paint::dim("  nothing stored to compare against"));
    } else {
        let built = v.indexes.as_ref().unwrap();
        let mut all_match = true;
        for (name, key) in INDEX_KEYS {
            let Some(want) = stored.get(name) else {
                println!("  {} {key}", paint::yellow("missing"));
                all_match = false;
                continue;
            };
            let Some(got) = built.by_name(name) else {
                continue;
            };
            // §13.2: `generated` and the per-entry `etag` are excluded.
            let same = want.comparable() == got.comparable();
            if same {
                println!("  {} {key}", paint::green("match  "));
            } else {
                println!("  {} {key}", paint::red("differs"));
                print_first_difference(&want.comparable(), &got.comparable());
                all_match = false;
            }
        }
        if !all_match {
            // A vault whose stored indexes do not reproduce is servable but
            // not trustworthy, so this is a failure the exit code reports.
            failed = true;
        }
    }

    // 4. ACL evaluation of a named principal against a named path (§8.7).
    let who = args.get("principal");
    let path = args.get("path");
    match (who, path) {
        (Some(who), Some(path)) => {
            println!(
                "\n{} {} {} {}",
                paint::bold("access"),
                paint::bold(who),
                paint::dim("on"),
                paint::bold(path)
            );
            let e = v.effective(who, path);
            let granted = e.granted();
            println!(
                "  granted: {}",
                if granted.is_empty() {
                    paint::red("(nothing)")
                } else {
                    paint::green(&granted.join(", "))
                }
            );
            for r in ["read", "list", "traverse", "write", "publish"] {
                let d = &e.decisions[r];
                let mark = match d.decision {
                    basalt::acl::Decision::Allow => paint::green("allow"),
                    basalt::acl::Decision::Deny => paint::red("deny "),
                };
                let at = d
                    .failed_at
                    .as_deref()
                    .map(|f| {
                        // The vault root is the empty folder path; spelling it
                        // "/" keeps the message readable.
                        format!(
                            " (traverse failed at {})",
                            if f.is_empty() { "/" } else { f }
                        )
                    })
                    .unwrap_or_default();
                println!("  {mark} {:<10} {}{at}", r, paint::dim(&d.by));
            }
        }
        _ => {
            println!(
                "\n{}",
                paint::dim("access      pass --principal ID --path P to evaluate the ACL (§8.7)")
            );
        }
    }

    println!();
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn print_first_difference(want: &Json, got: &Json) {
    let w = want.to_canonical_string();
    let g = got.to_canonical_string();
    let wl: Vec<&str> = w.lines().collect();
    let gl: Vec<&str> = g.lines().collect();
    for i in 0..wl.len().max(gl.len()) {
        let a = wl.get(i).copied().unwrap_or("<missing>");
        let b = gl.get(i).copied().unwrap_or("<missing>");
        if a != b {
            println!("{}", paint::dim(&format!("      line {}", i + 1)));
            println!("{}", paint::dim(&format!("      stored {a}")));
            println!("{}", paint::dim(&format!("      built  {b}")));
            return;
        }
    }
}
