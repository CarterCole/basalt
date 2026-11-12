//! The basalt CLI.
//!
//! `basalt check` is the self-check PROTOCOL §14.3 *requires* of a conforming
//! implementation, not an optional nicety: it is the tool a vault owner runs
//! to answer "is my private note actually private", and without it the answer
//! is unknowable.

use basalt::acl::RIGHTS;
use basalt::canonical::Json;
use basalt::frontmatter::Severity;
use basalt::serve::router::SurfaceKind;
use basalt::transport::{FsTransport, Transport};
use basalt::vault::{IndexState, Vault, INDEX_KEYS};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
basalt — a Rust implementation of the Basalt Protocol v1 (conformance L0-L4)

  basalt check    [--vault DIR | --git DIR | --bucket B] [--principal ID] [--path P]
                  Self-check (§14.3): integrity, index freshness, whether a
                  rebuild reproduces the stored indexes byte for byte, and the
                  ACL evaluation of a principal against a path.

  basalt index    [--vault DIR | --git DIR | --bucket B] [--write] [--force]
                  Rebuild every index from content alone. --write persists.
                  §10.7 refuses to replace a non-empty stored index with an
                  empty one; --force overrides that, and almost never should.

  basalt mint     [--vault DIR | --git DIR | --bucket B]
                  Mint node ids for unbound objects (§4.3).

  basalt add      <FILE>... [--to FOLDER/] [--vault DIR | --git DIR | --bucket B]
                  [--title T] [--alt A] [--principal ID]
                  [--agent LABEL] [--account LABEL]
                  basalt add - --as PATH        (content from stdin)
                  Store a note, an image or any other file as a NEW object
                  (§12.7): it gets an id, an entry sidecar if it cannot carry
                  frontmatter, and the indexes are refreshed. Never
                  overwrites. Without --to, notes go to Notes/ and everything
                  else to Assets/. --as gives the exact vault path of a single
                  file. Without --principal you act as the operator who holds
                  the vault's credentials; with it, that principal's
                  create_child right on the folder is enforced. --agent and
                  --account stamp the new object \"created_by\" with those
                  labels. On AWS S3 the stamp also names the caller: the ARN
                  AWS reports for the credentials doing the write.

  basalt gist export FOLDER/ | --whole  [--update ID [--prune]] [--public]
                  [--description TEXT] [--dry-run] [--principal ID]
                  [--vault DIR | --git DIR | --bucket B]
                  Send a vault folder to a GitHub gist: a NEW secret gist, or
                  --update to write into one you already have. A gist is flat
                  and holds non-empty text, so a file's path inside FOLDER/
                  becomes one file name (\"Notes/A.md\" is \"Notes%2FA.md\"), and
                  a binary or empty file is left out and listed, never dropped
                  silently. --whole sends every key of the vault, so the gist
                  opens as a vault with --gist. A secret gist is unlisted, not
                  private: anyone with its URL can read it, whatever
                  basalt.yaml says. --public lists it. --dry-run prints what
                  would be sent and sends nothing. --update only adds and
                  changes files; --prune also removes the gist's files the
                  folder no longer has. --principal sends only what that
                  principal may read. The token is read from GITHUB_TOKEN or
                  GH_TOKEN (or `gh auth token`), never from a flag.

  basalt gist import ID|URL [--to FOLDER/] [--principal ID]
                  [--agent LABEL] [--account LABEL]
                  [--vault DIR | --git DIR | --bucket B]
                  Store every file of a gist as a NEW object under FOLDER/
                  (default Gists/<id>/), as `basalt add` does: each gets an
                  id, and one whose path is taken is refused, never replaced.
                  A public or secret gist needs no token to read.

  basalt serve    [--vault DIR | --git DIR | --bucket B] [--port N] [--principal ID]
                  [--surfaces LIST]
                  Run the gatekeeper (§12) and the interop surfaces it
                  declares: REST with an OpenAPI 3.1 document (P-REST) and the
                  Model Context Protocol over HTTP (P-MCP). --principal forces
                  an identity for local testing; without it every request is
                  anonymous. Without --surfaces the vault's own
                  publish.interop decides; --surfaces rest,mcp overrides it.

  basalt mcp      [--vault DIR | --git DIR | --bucket B] [--principal ID] [--writable]
                  [--agent LABEL] [--account LABEL]
                  Serve one vault to an MCP client over stdio (INTEROP §4.2).
                  stdout carries JSON-RPC and nothing else; diagnostics go to
                  stderr. The principal is fixed for the life of the process.
                  --writable adds basalt_store, which creates new notes,
                  images and files (never overwrites) subject to that
                  principal's ACL; it requires --principal. --agent and
                  --account name who is behind this process (\"claude-code\",
                  \"work\"): every object it creates is stamped \"created_by\"
                  with them, the principal, the time, and what the client
                  called itself. Labels, not emails. On AWS S3 it also records
                  the caller, the ARN AWS reports for the process's
                  credentials.

  basalt schema   <openapi|discovery> [--vault DIR] [--base URL]
                  Print the machine-readable description of a surface: the
                  OpenAPI 3.1 document the server serves at
                  /api/v1/openapi.json, or the /.well-known/basalt discovery
                  document. The GraphQL SDL and the protobuf service belong to
                  surfaces this implementation does not serve; see
                  protocol/INTEROP.md.

  basalt effective --path P [--principal ID]
                  Effective rights with the deciding ACE per right (§8.7).

  basalt tree     [--principal ID]
                  The visible tree for a principal.

  basalt export   [--vault DIR] --out DIR [--vault-id ULID]
                  Export the public subset as a complete, servable vault
                  (§12.6): only nodes granting read and publish to anonymous,
                  with every index regenerated rather than copied (§8.8).

  basalt digest   Print the merkle root over content/ (§10.6).

Stores (pick one; every command takes the same flags):
  --vault DIR                        a local folder (the default: .)
  --git DIR                          a folder in a git working tree. Reads come
                                     from disk; each write (a stored note, a
                                     reindex, a mint) is one commit, made with
                                     your git identity, of only the files
                                     basalt wrote. Files .gitignore excludes
                                     are written but not committed.
    --remote NAME                    also pull before each write and push
                                     after it (never forced). Offline or
                                     rejected, the write still succeeds and the
                                     commit goes with the next push. Pushing
                                     copies the vault to that remote: a private
                                     audience is enforced by basalt's server,
                                     not by the git host.
  --bucket NAME [--prefix P/]        an S3-compatible store, with
    [--endpoint URL] [--region R]    --flavor s3|minio|r2 (needs --features s3)
  --gist ID|URL                      a whole vault inside one gist (made with
    [--api-url URL]                  `gist export --whole`). Text only, at most
                                     300 files; a batch of writes is one gist
                                     revision. Writes need GITHUB_TOKEN.
                                     --api-url points at GitHub Enterprise.
";

struct Args {
    cmd: String,
    flags: BTreeMap<String, String>,
    bare: Vec<String>,
}

/// Flags that never take a value, so the word after one is a positional.
const BOOL_FLAGS: [&str; 4] = ["whole", "public", "dry-run", "prune"];

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
                if BOOL_FLAGS.contains(&name) {
                    flags.insert(name.to_string(), "true".into());
                    i += 1;
                    continue;
                }
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

/// Build a transport from flags. One store per process: --vault for a plain
/// folder (the default, "."), --git for a folder in a git working tree,
/// --bucket for S3, MinIO or R2, --gist for a GitHub gist.
fn transport(args: &Args) -> Result<Box<dyn Transport>, String> {
    let given: Vec<&str> = ["vault", "git", "bucket", "gist"].into_iter().filter(|n| args.get(n).is_some()).collect();
    if given.len() > 1 {
        let named: Vec<String> = given.iter().map(|n| format!("--{n}")).collect();
        return Err(format!("pick one store: {} were both given", named.join(" and ")));
    }
    for n in ["vault", "git", "bucket", "gist", "remote", "api-url"] {
        if args.get(n) == Some("true") {
            return Err(format!("--{n} needs a value"));
        }
    }
    if args.get("remote").is_some() && args.get("git").is_none() {
        return Err("--remote is for a git store (--git DIR)".into());
    }
    if let Some(dir) = args.get("git") {
        use basalt::transport::GitTransport;
        // Indexes are rebuilt from content (§10), so a merge that conflicts
        // only in them keeps this side's and lets the next reindex settle it.
        let t = GitTransport::new(dir, args.get("remote").map(str::to_string), vec![basalt::keys::INDEX.to_string()]);
        // Checks it is in a working tree and, with --remote, pulls.
        t.ready().map_err(|e| e.to_string())?;
        return Ok(Box::new(t));
    }
    if let Some(id) = args.get("gist") {
        #[cfg(feature = "gist")]
        {
            use basalt::transport::GistTransport;
            let t = GistTransport::new(id, gist_api(args)?).map_err(|e| e.to_string())?;
            // Reads the gist now, and refuses one too big for the API to list.
            t.ready().map_err(|e| e.to_string())?;
            return Ok(Box::new(t));
        }
        #[cfg(not(feature = "gist"))]
        {
            let _ = id;
            return Err("this build has no gist support; rebuild with --features gist, or use --vault".to_string());
        }
    }
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

/// The GitHub client. The token comes from the environment, never a flag.
#[cfg(feature = "gist")]
fn gist_api(args: &Args) -> Result<basalt::transport::GistApi, String> {
    if args.get("api-url") == Some("true") {
        return Err("--api-url needs a value".into());
    }
    basalt::transport::GistApi::new(args.get("api-url")).map_err(|e| e.to_string())
}

fn open(args: &Args) -> Result<Vault, String> {
    Vault::open(transport(args)?).map_err(|e| e.to_string())
}

/// Where the vault is, for the `basalt mcp` startup line.
fn where_line(args: &Args) -> String {
    if args.get("git").is_none() {
        return String::new();
    }
    match args.get("remote") {
        Some(r) => format!(" (git, syncing with {r})"),
        None => " (git, local only)".to_string(),
    }
}

fn label(args: &Args, name: &str) -> Result<Option<String>, String> {
    basalt::store::check_provenance_label(&format!("--{name}"), args.get(name)).map_err(|e| e.detail)
}

/// What the store says the credentials behind this process belong to
/// (§12.7 `caller`), asked once: every write this process makes is signed
/// with the same credentials. A store that cannot say gives nothing; one that
/// fails to answer is reported and the writes go ahead without it.
fn lookup_caller(v: &Vault) -> Option<String> {
    match v.transport.caller_identity() {
        Ok(found) => match basalt::store::normalize_caller(found.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("basalt: could not name the caller, so writes will not record one: {}", e.detail);
                None
            }
        },
        Err(e) => {
            eprintln!("basalt: could not name the caller, so writes will not record one: {e}");
            None
        }
    }
}

/// `basalt add`: store files as NEW objects (§12.7).
fn add(args: &Args) -> Result<ExitCode, String> {
    use basalt::frontmatter::{kind_for, Kind};
    use basalt::store::{store_object, Provenance, StoreRequest};
    use basalt::transport::BatchInfo;
    use std::io::Read;
    use unicode_normalization::UnicodeNormalization;

    let sources = args.bare.clone();
    if sources.is_empty() {
        return Err("add needs a file to store, or - for stdin with --as PATH".into());
    }
    let as_path = args.get("as").map(str::to_string);
    let to = args.get("to").map(str::to_string);
    let title = args.get("title").map(str::to_string);
    let alt = args.get("alt").map(str::to_string);
    if as_path.is_some() && to.is_some() {
        return Err("--as names the whole path; --to names only the folder".into());
    }
    if sources.len() > 1 && (as_path.is_some() || title.is_some() || alt.is_some()) {
        return Err("--as, --title and --alt describe one file; add several with --to FOLDER/".into());
    }
    // No --principal: you are the operator, who holds the credentials and
    // could write the file by hand. With one, §8 applies as for anyone.
    let principal = args.get("principal").map(str::to_string);
    let agent = label(args, "agent")?;
    let account = label(args, "account")?;
    let mut v = open(args)?;
    // Stamp only when there is something true to say: the labels typed, or
    // the caller the store names.
    let caller = lookup_caller(&v);
    if let Some(c) = &caller {
        println!("{}", paint::dim(&format!("storing as {c}")));
    }
    let provenance = (agent.is_some() || account.is_some() || caller.is_some())
        .then_some(Provenance { agent, account, caller, client: None });
    let folder_for = |name: &str| -> String {
        match &to {
            None => if kind_for(name) == Kind::Note { "Notes/".into() } else { "Assets/".into() },
            Some(f) => {
                let f = f.trim_start_matches('/');
                if f.is_empty() || f.ends_with('/') { f.to_string() } else { format!("{f}/") }
            }
        }
    };
    let size = |n: usize| {
        if n < 1024 { format!("{n} B") }
        else if n < 1_048_576 { format!("{:.1} KB", n as f64 / 1024.0) }
        else { format!("{:.1} MB", n as f64 / 1_048_576.0) }
    };

    let mut stored_paths: Vec<String> = Vec::new();
    let mut refused = 0;
    let trailers = principal.iter().map(|p| ("Basalt-Principal".to_string(), p.clone())).collect();
    v.transport.begin_batch().map_err(|e| e.to_string())?;
    for src in &sources {
        let attempt = (|| -> Result<basalt::store::Stored, String> {
            let (bytes, name) = if src == "-" {
                if as_path.is_none() {
                    return Err("content from stdin needs --as PATH".into());
                }
                let mut b = Vec::new();
                std::io::stdin().read_to_end(&mut b).map_err(|e| e.to_string())?;
                (b, String::new())
            } else {
                let p = std::path::Path::new(src);
                if p.is_dir() {
                    return Err("is a directory; add the files in it".into());
                }
                let b = std::fs::read(p).map_err(|e| e.to_string())?;
                // macOS hands out decomposed (NFD) filenames, which §1.1 rejects.
                let n: String = p.file_name().map(|f| f.to_string_lossy().nfc().collect()).unwrap_or_default();
                (b, n)
            };
            let dest = as_path.clone().unwrap_or_else(|| format!("{}{name}", folder_for(&name)));
            store_object(
                &mut v,
                &StoreRequest {
                    principal: principal.as_deref(),
                    path: &dest,
                    bytes: &bytes,
                    title: title.as_deref(),
                    alt: alt.as_deref(),
                    provenance: provenance.as_ref(),
                    reindex: false,
                    max_bytes: None,
                },
            )
            .map_err(|e| e.to_string())
        })();
        match attempt {
            Ok(r) => {
                println!(
                    "{}  {}  {}",
                    paint::green("stored"),
                    r.path,
                    paint::dim(&format!("{}  {}, {}", r.id, r.kind.as_str(), size(r.size)))
                );
                stored_paths.push(r.path);
            }
            Err(e) => {
                refused += 1;
                eprintln!("{} {}: {e}", paint::red("refused"), if src == "-" { "stdin" } else { src.as_str() });
            }
        }
    }
    let mut failure = None;
    if !stored_paths.is_empty() {
        // One index pass for the whole command.
        match v.reindex(true) {
            Ok(()) => {
                let issues = &v.indexes.as_ref().unwrap().issues;
                let errs = issues.iter().filter(|i| i.severity == basalt::frontmatter::Severity::Error).count();
                println!("{}", paint::dim(&format!("indexes refreshed · integrity {errs} errors, {} warnings", issues.len() - errs)));
            }
            Err(e) => failure = Some(format!("stored, but refreshing the indexes failed: {e}. Run `basalt index --write`.")),
        }
    }
    let message = match stored_paths.len() {
        0 => None,
        1 => Some(format!("Add {}", stored_paths[0])),
        n => Some(format!("Add {n} files")),
    };
    if let Err(e) = v.finish_batch(&BatchInfo { message, trailers }) {
        failure.get_or_insert(e.to_string());
    }
    if let Some(f) = failure {
        return Err(f);
    }
    Ok(if refused > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// `basalt gist export | import`: copy a folder to a gist, or a gist into one.
#[cfg(feature = "gist")]
fn gist(args: &Args) -> Result<ExitCode, String> {
    use basalt::gist::{export_to_gist, folder_path, import_from_gist, ExportArgs};
    use basalt::store::Provenance;
    use basalt::transport::gist::parse_gist_id;

    if args.flags.keys().any(|k| k == "token" || k.starts_with("token=")) {
        // A token on the command line lands in shell history and `ps`.
        return Err("there is no --token flag: set GITHUB_TOKEN (or GH_TOKEN), or sign in with `gh auth login`".into());
    }
    let sub = args.bare.first().map(String::as_str).unwrap_or("");
    let rest: Vec<&String> = args.bare.iter().skip(1).collect();
    let api = gist_api(args)?;
    let principal = args.get("principal").filter(|p| !p.is_empty());
    let size = |n: usize| {
        if n < 1024 { format!("{n} B") }
        else if n < 1_048_576 { format!("{:.1} KB", n as f64 / 1024.0) }
        else { format!("{:.1} MB", n as f64 / 1_048_576.0) }
    };
    let why = |reason: &str| match reason {
        "empty" => "empty",
        "not_text" => "not text a gist can hold",
        "name_too_long" => "name too long",
        "invalid_key" => "not a valid vault path",
        other => other,
    }
    .to_string();
    let skipped_lines = |skipped: &[basalt::gist::Skipped]| {
        if skipped.is_empty() {
            return;
        }
        println!("{}", paint::yellow(&format!("left out {} file(s) a gist cannot hold:", skipped.len())));
        for s in skipped.iter().take(20) {
            println!("{}", paint::yellow(&format!("  {}  ({})", s.path, why(s.reason))));
        }
        if skipped.len() > 20 {
            println!("{}", paint::dim(&format!("  …{} more", skipped.len() - 20)));
        }
    };
    let value = |name: &str| -> Result<Option<&str>, String> {
        match args.get(name) {
            Some("true") => Err(format!("--{name} needs a value")),
            v => Ok(v),
        }
    };

    match sub {
        "export" => {
            let whole = args.on("whole");
            if if whole { !rest.is_empty() } else { rest.len() != 1 } {
                return Err("gist export needs one folder (e.g. Projects/), or --whole".into());
            }
            let update = match value("update")? {
                None => None,
                Some(u) => Some(parse_gist_id(u).ok_or("--update needs a gist id or URL")?),
            };
            let description = value("description")?;
            let mut v = open(args)?;
            // A principal's view needs inline ACLs, which come from a reindex.
            if principal.is_some() {
                v.reindex(false).map_err(|e| e.to_string())?;
            }
            let folder = if whole { String::new() } else { folder_path(rest[0]) };
            let r = export_to_gist(
                &v,
                &api,
                &ExportArgs {
                    folder: &folder,
                    whole,
                    update: update.as_deref(),
                    prune: args.on("prune"),
                    public: args.on("public"),
                    description,
                    principal,
                    dry_run: args.on("dry-run"),
                },
            )?;
            let place = if r.public { paint::red("PUBLIC") } else { "secret".to_string() };
            if r.dry_run {
                println!(
                    "would send {} file(s), {}, as a new {place} gist{}",
                    r.count,
                    size(r.bytes),
                    paint::dim(" (nothing sent: --dry-run)")
                );
                for n in &r.names {
                    println!("  {n}");
                }
            }
            skipped_lines(&r.skipped);
            if r.withheld > 0 {
                println!(
                    "{}",
                    paint::dim(&format!("{} file(s) withheld: {} may not read them", r.withheld, principal.unwrap_or("")))
                );
            }
            if !r.dry_run {
                let url = r.url.clone().or(r.id.clone()).unwrap_or_default();
                if r.created {
                    println!("{} {place} gist {url}", paint::green("created"));
                    println!(
                        "{}",
                        paint::dim(&format!(
                            "  {} file(s), {}{}",
                            r.count,
                            size(r.bytes),
                            if r.public {
                                ". It is public: anyone can find and read it."
                            } else {
                                ". Secret means unlisted, not private: anyone with the URL can read it."
                            }
                        ))
                    );
                } else if !r.updated {
                    println!(
                        "{}  {url}  {}",
                        paint::green("up to date"),
                        paint::dim(&format!("{} file(s) unchanged", r.unchanged))
                    );
                } else {
                    println!("{} {place} gist {url}", paint::green("updated"));
                    println!(
                        "{}",
                        paint::dim(&format!(
                            "  {} written, {} unchanged{}",
                            r.written,
                            r.unchanged,
                            if r.removed > 0 { format!(", {} removed", r.removed) } else { String::new() }
                        ))
                    );
                }
                if !r.left.is_empty() {
                    println!(
                        "{}",
                        paint::yellow(&format!(
                            "{} file(s) in the gist are not in the folder (--prune removes them): {}{}",
                            r.left.len(),
                            r.left.iter().take(5).cloned().collect::<Vec<_>>().join(", "),
                            if r.left.len() > 5 { ", …" } else { "" }
                        ))
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        "import" => {
            if rest.len() != 1 {
                return Err("gist import needs one gist id or URL".into());
            }
            let id = parse_gist_id(rest[0]).ok_or_else(|| format!("not a gist id or URL: {}", rest[0]))?;
            let agent = label(args, "agent")?;
            let account = label(args, "account")?;
            let mut v = open(args)?;
            let caller = lookup_caller(&v);
            let provenance = (agent.is_some() || account.is_some() || caller.is_some())
                .then_some(Provenance { agent, account, caller, client: None });
            let to = match value("to")? {
                None => format!("Gists/{id}/"),
                Some(t) => folder_path(t),
            };
            let r = import_from_gist(&mut v, &api, &id, &to, principal, provenance.as_ref(), |o| {
                println!(
                    "{}  {}  {}",
                    paint::green("stored"),
                    o.path,
                    paint::dim(&format!("{}  {}, {}", o.id, o.kind.as_str(), size(o.size)))
                );
            })?;
            for (name, why) in &r.refused {
                eprintln!("{} {name}: {why}", paint::red("refused"));
            }
            println!(
                "{}",
                paint::dim(&format!(
                    "{} stored, {} refused, from {} gist {}{}",
                    r.stored.len(),
                    r.refused.len(),
                    if r.gist.public { "public" } else { "secret" },
                    r.gist.url.clone().unwrap_or_else(|| r.gist.id.clone()),
                    if r.stored.is_empty() { "" } else { " · indexes refreshed" }
                ))
            );
            Ok(if r.refused.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) })
        }
        _ => Err("gist takes export or import (basalt gist export FOLDER/, basalt gist import ID)".into()),
    }
}

#[cfg(not(feature = "gist"))]
fn gist(_args: &Args) -> Result<ExitCode, String> {
    Err("this build has no gist support; rebuild with --features gist".into())
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
            // Left out, the manifest's publish.interop decides (§3.1); a
            // manifest that says nothing serves the §12 read API alone,
            // because profiles are opt-in (§14.1).
            if let Some(list) = args.get("surfaces") {
                gk = gk.with_surfaces(parse_surfaces(list)?);
            }
            gk.set_index_state(state);
            let addr = format!("127.0.0.1:{}", args.or("port", "4380"));
            println!(
                "{} {} {}",
                paint::bold("gatekeeper"),
                paint::dim(&format!("vault {vault_id}")),
                paint::dim(&format!("index {}", state.as_str()))
            );
            for kind in SurfaceKind::ALL {
                if !gk.router().has(kind) {
                    continue;
                }
                let line = match kind {
                    SurfaceKind::Rest => "GET  /api/v1/{manifest,me,tree,nodes,node/<path>,raw/<path>,list/<folder>,links/<path>,search?q=,tags,effective?path=}",
                    SurfaceKind::Mcp => "POST /mcp              · or `basalt mcp` over stdio",
                };
                println!("  {}", paint::dim(line));
            }
            println!(
                "  {}",
                paint::dim(&format!("every surface at once: http://{addr}/.well-known/basalt"))
            );
            Arc::new(gk).listen(&addr).map_err(|e| e.to_string())?;
            Ok(ExitCode::SUCCESS)
        }
        "mcp" => {
            use basalt::serve::mcp;
            use basalt::serve::surface::Surface;
            let mut v = open(args)?;
            let state = v.ensure_indexes().map_err(|e| e.to_string())?;
            let vault_id = v.manifest.vault_id.clone();
            let principal = args.or("principal", "anonymous");
            let writable = args.on("writable");
            let agent = label(args, "agent")?;
            let account = label(args, "account")?;
            if (agent.is_some() || account.is_some()) && !writable {
                return Err("--agent and --account label what this process writes; they need --writable".into());
            }
            if writable && principal == "anonymous" {
                // An anonymous writer is whatever the ACL lets anonymous do,
                // which for a vault never meant to be written is nothing: fail
                // here instead of offering a tool that always refuses.
                return Err("--writable needs --principal ID: a write is judged against who made it".into());
            }
            let caller = if writable { lookup_caller(&v) } else { None };
            let surface = Surface::new(v);
            surface.set_index_state(state);
            // stdout is the JSON-RPC channel, so the startup line goes to
            // stderr: anything else there breaks the framing (INTEROP §4.2.1).
            let mut note = String::new();
            if writable {
                let who: Vec<String> = [agent.as_ref().map(|a| format!("agent {a}")), account.as_ref().map(|a| format!("account {a}"))]
                    .into_iter()
                    .flatten()
                    .collect();
                note = format!(
                    " (may create notes, images and files; {}{})",
                    if who.is_empty() { "stamped with no agent or account, see --agent/--account".to_string() } else { format!("stamped {}", who.join(", ")) },
                    caller.as_ref().map(|c| format!("; caller {c}")).unwrap_or_default()
                );
            }
            eprintln!("basalt mcp: vault {vault_id}{} as {principal}{note}", where_line(args));
            let methods = mcp::methods_with(
                &surface,
                &principal,
                env!("CARGO_PKG_VERSION"),
                mcp::McpOptions { writable, agent, account, caller },
            );
            methods.serve_stdio().map_err(|e| e.to_string())?;
            Ok(ExitCode::SUCCESS)
        }
        "add" => add(args),
        "gist" => gist(args),
        "schema" => {
            use basalt::serve::router::Router;
            use basalt::serve::surface::Surface;
            let which = args.bare.first().cloned().unwrap_or_default();
            let base = args.or("base", "http://127.0.0.1:4380");
            let mut v = open(args)?;
            match which.as_str() {
                "openapi" => {
                    let router = Router::new(Surface::new(v));
                    print!("{}", router.openapi(&base).to_canonical_string());
                }
                "discovery" => {
                    let state = v.ensure_indexes().map_err(|e| e.to_string())?;
                    let router = Router::new(Surface::new(v));
                    router.surface.set_index_state(state);
                    print!("{}", router.discovery(&base).to_canonical_string());
                }
                other => {
                    return Err(format!(
                        "schema takes one of: openapi, discovery (got {other:?})"
                    ))
                }
            }
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

/// `--surfaces rest,mcp` — the operator's override of what the manifest
/// declares (INTEROP §10).
fn parse_surfaces(list: &str) -> Result<std::collections::BTreeSet<SurfaceKind>, String> {
    let mut out = std::collections::BTreeSet::new();
    for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        match SurfaceKind::parse(name) {
            Some(kind) => {
                out.insert(kind);
            }
            None => {
                let known: Vec<&str> = SurfaceKind::ALL.iter().map(|k| k.as_str()).collect();
                return Err(format!(
                    "unknown surface {name:?}; this implementation serves: {}",
                    known.join(", ")
                ));
            }
        }
    }
    Ok(out)
}
