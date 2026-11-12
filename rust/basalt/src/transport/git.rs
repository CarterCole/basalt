//! Git working-tree transport, PROTOCOL §1.
//!
//! The vault is a folder inside a git working tree, so it stays plain
//! markdown that Obsidian, an editor, `rg` and `git` itself can open. Reads
//! come straight from disk through [`FsTransport`], so an edit made by hand is
//! seen at once. Writes land on disk exactly as they do there and are then
//! committed, which buys what a folder lacks: every superseded version is
//! kept, and the vault can be cloned, pushed and shared.
//!
//! What it commits, and what it leaves alone:
//!
//! - Only the keys this transport wrote. A partial commit (`git commit --
//!   <paths>`) leaves anything else staged or edited exactly as it was.
//! - Not a key git ignores. A vault that lists `index/` in `.gitignore` still
//!   gets its indexes written to disk, but not committed.
//! - One commit per logical write: a batch groups a stored note, its sidecar
//!   and the refreshed indexes. A put outside a batch is committed alone.
//!
//! With a remote, writes are local-first: before a batch it fetches and
//! fast-forwards (or merges); after it, it pushes. It never forces, rebases
//! or rewrites history. When it cannot sync — offline, a rejected push, a
//! real conflict — the write still succeeds, because the working tree *is*
//! the store; the problem is reported and the next push carries it out.
//!
//! This is the TypeScript reference's git store, made synchronous: the batch
//! is a depth counter instead of async-local context, and one batch at a time
//! per working tree is kept by a lock file in the git dir, which also keeps a
//! second process (another `basalt mcp`, a `basalt add`) out of the way.

use super::fs::FsTransport;
use super::{BatchEnd, BatchInfo, Capability, ListOpts, Listing, PutMeta, Result, Stat, Transport, TransportError};
use crate::keys::validate_key;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

/// How long a view of HEAD, the tracked tree and the dirty set is reused.
const SNAPSHOT_TTL: Duration = Duration::from_secs(1);
/// A fetch or push not finished by now is given up on; the commit is kept.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);
/// Pushes tried (each after pulling what beat it) before leaving it.
const PUSH_ATTEMPTS: usize = 5;
/// How long a write waits for another process's, and when a lock is abandoned.
const LOCK_WAIT: Duration = Duration::from_secs(5 * 60);
const LOCK_STALE: Duration = Duration::from_secs(10 * 60);

fn lock_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\.lock'?: File exists|Unable to create '[^']*\.lock'|could not lock config file|cannot lock ref 'HEAD'").unwrap()
    })
}

/// A push turned down because the remote moved on, or another push was
/// updating the branch at the same moment. Either way: pull, push again.
fn rejected_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\[rejected\]|non-fast-forward|fetch first|\[remote rejected\]|cannot lock ref|failed to update ref").unwrap()
    })
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Default)]
struct Init {
    top: PathBuf,
    /// The vault root relative to the top of the repository, with a trailing
    /// slash, or empty when the root is the top.
    prefix: String,
    lock_path: PathBuf,
    remote_url: Option<String>,
}

struct Snapshot {
    head: String,
    tracked: BTreeSet<String>,
    times: BTreeMap<String, String>,
    dirty: BTreeSet<String>,
    at: Instant,
}

#[derive(Default)]
struct BatchState {
    depth: usize,
    keys: BTreeSet<String>,
    /// The contents of the lock file while this process holds it.
    lock: Option<String>,
}

pub struct GitTransport {
    root: PathBuf,
    fs: FsTransport,
    remote: Option<String>,
    derived: Vec<String>,
    caps: BTreeSet<Capability>,
    init: Mutex<Option<Init>>,
    batch: Mutex<BatchState>,
    snap: Mutex<Option<Snapshot>>,
    /// A push was put off (a merge needed the indexes rebuilt first); the
    /// next batch pushes even if it commits nothing.
    owe_push: Mutex<bool>,
    warn: Box<dyn Fn(&str) + Send + Sync>,
}

impl GitTransport {
    /// `root` is the vault root, inside a git working tree (not necessarily
    /// its top). `remote` names a git remote to pull from and push to; left
    /// out, nothing leaves this machine. `derived` are key prefixes rebuilt
    /// from the rest (`index/`): a merge that conflicts only in them keeps
    /// this side's, and the vault's next reindex settles them.
    pub fn new(root: impl AsRef<Path>, remote: Option<String>, derived: Vec<String>) -> Self {
        let root = root.as_ref().to_path_buf();
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        let fs = FsTransport::new(&root);
        let mut caps = fs.capabilities().clone();
        // §1's `versioning`: every committed version is retained.
        caps.insert(Capability::Versioning);
        Self {
            root,
            fs,
            remote: remote.filter(|r| !r.is_empty()),
            derived,
            caps,
            init: Mutex::new(None),
            batch: Mutex::new(BatchState::default()),
            snap: Mutex::new(None),
            owe_push: Mutex::new(false),
            warn: Box::new(|m| eprintln!("basalt: {m}")),
        }
    }

    /// Where sync problems are reported; stderr by default.
    pub fn with_warn(mut self, warn: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.warn = Box::new(warn);
        self
    }

    pub fn remote(&self) -> Option<&str> {
        self.remote.as_deref()
    }

    /// The remote's URL, once [`GitTransport::ready`] has run.
    pub fn remote_url(&self) -> Option<String> {
        self.init.lock().unwrap().as_ref().and_then(|i| i.remote_url.clone())
    }

    // ---------------------------------------------------------------- git

    fn run(&self, args: &[&str], cwd: &Path, input: Option<&[u8]>, timeout: Option<Duration>) -> Result<Out> {
        let mut child = Command::new("git")
            .args(args)
            .current_dir(cwd)
            // Never wait on a person: no editor, no credential prompt. Messages
            // are matched below, so keep them in one language.
            .env("GIT_EDITOR", "true")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    TransportError::Backend("the git store needs git on PATH".into())
                } else {
                    TransportError::Io(e)
                }
            })?;
        let mut stdin = child.stdin.take().unwrap();
        let input = input.map(<[u8]>::to_vec).unwrap_or_default();
        let feeder = std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
        let mut so = child.stdout.take().unwrap();
        let mut se = child.stderr.take().unwrap();
        let out_t = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = so.read_to_end(&mut b);
            b
        });
        let err_t = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = se.read_to_end(&mut b);
            b
        });
        let started = Instant::now();
        let mut timed_out = false;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if timeout.is_some_and(|t| started.elapsed() > t) {
                let _ = child.kill();
                timed_out = true;
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let _ = feeder.join();
        let stdout = String::from_utf8_lossy(&out_t.join().unwrap_or_default()).into_owned();
        let mut stderr = String::from_utf8_lossy(&err_t.join().unwrap_or_default()).into_owned();
        if timed_out {
            stderr = format!("timed out after {}s", timeout.unwrap().as_secs());
        }
        Ok(Out { code: status.code().unwrap_or(-1), stdout, stderr })
    }

    /// Run git in the vault root. Every pathspec is literal, so a note called
    /// `[draft] *.md` is that file and not a glob. `ok` lists the exit codes
    /// that are not failures; None accepts any.
    fn git(&self, args: &[&str], ok: Option<&[i32]>, input: Option<&[u8]>, timeout: Option<Duration>) -> Result<Out> {
        self.git_in(&self.root.clone(), args, ok, input, timeout)
    }

    fn git_in(&self, cwd: &Path, args: &[&str], ok: Option<&[i32]>, input: Option<&[u8]>, timeout: Option<Duration>) -> Result<Out> {
        let mut argv = vec!["--literal-pathspecs"];
        argv.extend_from_slice(args);
        for attempt in 0.. {
            let r = self.run(&argv, cwd, input, timeout)?;
            if r.code != 0 && lock_re().is_match(&r.stderr) && attempt < 8 {
                // Another git process holds a lock for a few milliseconds; a
                // failed command here changed nothing.
                std::thread::sleep(Duration::from_millis(25 * (1 << attempt) + jitter(25)));
                continue;
            }
            if let Some(ok) = ok {
                if !ok.contains(&r.code) {
                    let why = first_line(&r.stderr)
                        .or_else(|| first_line(&r.stdout))
                        .unwrap_or_else(|| format!("exit {}", r.code));
                    return Err(TransportError::Backend(format!("git {} failed: {why}", args[0])));
                }
            }
            return Ok(r);
        }
        unreachable!()
    }

    /// Check, once, that the root is inside a working tree, and with a remote,
    /// pull. A failed check is not remembered: the next call tries again.
    pub fn ready(&self) -> Result<()> {
        if self.init.lock().unwrap().is_some() {
            return Ok(());
        }
        if !self.root.exists() {
            return Err(TransportError::Backend(format!("{} does not exist", self.root.display())));
        }
        let r = self.git(&["rev-parse", "--is-bare-repository", "--is-inside-work-tree"], None, None, None)?;
        if r.code != 0 {
            return Err(TransportError::Backend(format!(
                "{} is not in a git repository: run `git init` there, or use --vault for a plain folder",
                self.root.display()
            )));
        }
        let mut lines = r.stdout.lines();
        let (bare, inside) = (lines.next().unwrap_or(""), lines.next().unwrap_or(""));
        if bare == "true" || inside != "true" {
            return Err(TransportError::Backend(format!(
                "{} is in a bare repository, or its .git folder; clone it and point the git store at the clone",
                self.root.display()
            )));
        }
        let top = PathBuf::from(self.git(&["rev-parse", "--show-toplevel"], Some(&[0]), None, None)?.stdout.trim());
        let real_top = std::fs::canonicalize(&top).unwrap_or(top.clone());
        let rel = self.root.strip_prefix(&real_top).map(Path::to_path_buf).unwrap_or_default();
        let rel = rel.to_string_lossy().replace('\\', "/");
        let prefix = if rel.is_empty() { String::new() } else { format!("{rel}/") };
        // Per working tree: what the lock protects is this tree's files,
        // index and HEAD.
        let git_dir = self.git(&["rev-parse", "--absolute-git-dir"], Some(&[0]), None, None)?.stdout.trim().to_string();
        let mut init = Init {
            top,
            prefix,
            lock_path: PathBuf::from(git_dir).join("basalt-write.lock"),
            remote_url: None,
        };
        if let Some(remote) = &self.remote {
            let u = self.git(&["remote", "get-url", remote], None, None, None)?;
            if u.code != 0 {
                return Err(TransportError::Backend(format!("git has no remote named {remote}")));
            }
            init.remote_url = Some(u.stdout.trim().to_string());
        }
        *self.init.lock().unwrap() = Some(init);
        if self.remote.is_some() {
            let lock = self.take_lock()?;
            let pulled = self.pull();
            self.release_lock(&lock);
            pulled?;
        }
        Ok(())
    }

    fn with_init<R>(&self, f: impl FnOnce(&Init) -> R) -> R {
        f(self.init.lock().unwrap().as_ref().expect("ready() ran"))
    }

    fn branch(&self) -> Result<Option<String>> {
        let r = self.git(&["symbolic-ref", "-q", "--short", "HEAD"], None, None, None)?;
        Ok((r.code == 0).then(|| r.stdout.trim().to_string()))
    }

    fn rev(&self, r: &str) -> Result<String> {
        let spec = format!("{r}^{{commit}}");
        let out = self.git(&["rev-parse", "-q", "--verify", &spec], None, None, None)?;
        Ok(if out.code == 0 { out.stdout.trim().to_string() } else { String::new() })
    }

    fn is_ancestor(&self, a: &str, b: &str) -> Result<bool> {
        Ok(self.git(&["merge-base", "--is-ancestor", a, b], Some(&[0, 1]), None, None)?.code == 0)
    }

    // ---------------------------------------------------------- snapshot

    fn snapshot(&self) -> Result<()> {
        let mut snap = self.snap.lock().unwrap();
        if snap.as_ref().is_some_and(|s| s.at.elapsed() < SNAPSHOT_TTL) {
            return Ok(());
        }
        let head = self.rev("HEAD")?;
        let (mut tracked, mut times) = match snap.take() {
            Some(s) if s.head == head && !head.is_empty() => (s.tracked, s.times),
            _ => (BTreeSet::new(), BTreeMap::new()),
        };
        if !head.is_empty() && tracked.is_empty() {
            let t = self.git(&["ls-tree", "-r", "-z", "--name-only", "HEAD"], Some(&[0]), None, None)?;
            tracked = split0(&t.stdout).collect();
            let log = self.git(
                &["log", "--pretty=format:%x1e%cI", "--name-only", "--no-renames", "-z", "--relative", "HEAD", "--", "."],
                Some(&[0]),
                None,
                None,
            )?;
            times = BTreeMap::new();
            for chunk in log.stdout.split('\x1e') {
                let Some(nl) = chunk.find('\n') else { continue };
                let when = utc(&chunk[..nl]);
                for p in split0(&chunk[nl + 1..]) {
                    times.entry(p).or_insert_with(|| when.clone());
                }
            }
        }
        let mut dirty = BTreeSet::new();
        if !head.is_empty() {
            let d = self.git(&["diff", "--name-only", "-z", "--no-renames", "--relative", "HEAD", "--", "."], Some(&[0]), None, None)?;
            dirty = split0(&d.stdout).collect();
        }
        *snap = Some(Snapshot { head, tracked, times, dirty, at: Instant::now() });
        Ok(())
    }

    fn invalidate(&self) {
        if let Some(s) = self.snap.lock().unwrap().as_mut() {
            s.at = Instant::now() - SNAPSHOT_TTL * 2;
        }
    }

    // ------------------------------------------------------------- locks

    /// Take the write lock for this working tree, waiting for another
    /// process's batch. A lock left by a process that is gone, or older than
    /// any batch could take, is broken — atomically, by rename, so two
    /// waiters cannot both take it.
    fn take_lock(&self) -> Result<String> {
        let file = self.with_init(|i| i.lock_path.clone());
        let mine = format!("{} {} {}\n", std::process::id(), crate::transport::fs::now_rfc3339(), crate::ulid());
        let started = Instant::now();
        for attempt in 0u64.. {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&file) {
                Ok(mut f) => {
                    f.write_all(mine.as_bytes())?;
                    return Ok(mine);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            let Ok(seen) = std::fs::read_to_string(&file) else { continue };
            let mut parts = seen.split_whitespace();
            let pid: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
            let age = std::fs::metadata(&file)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .unwrap_or_default();
            if !alive(pid) || age > LOCK_STALE {
                let grave = file.with_extension(format!("lock.{}.{}", std::process::id(), crate::ulid()));
                match std::fs::rename(&file, &grave) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                }
                let moved = std::fs::read_to_string(&grave).ok();
                if moved.as_deref() != Some(seen.as_str()) {
                    // A live lock taken in between: put it back unless another
                    // has already replaced it.
                    let _ = std::fs::hard_link(&grave, &file);
                }
                let _ = std::fs::remove_file(&grave);
                continue;
            }
            if started.elapsed() > LOCK_WAIT {
                return Err(TransportError::Backend(format!(
                    "another basalt process (pid {pid}) has been writing to this clone for {}s; if it is gone, remove {}",
                    age.as_secs(),
                    file.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(20 + (attempt * 10).min(230) + jitter(20)));
        }
        unreachable!()
    }

    /// Remove the lock only while it is still ours.
    fn release_lock(&self, mine: &str) {
        let file = self.with_init(|i| i.lock_path.clone());
        if std::fs::read_to_string(&file).ok().as_deref() == Some(mine) {
            let _ = std::fs::remove_file(&file);
        }
    }

    // ------------------------------------------------------------ commits

    fn commit(&self, keys: &BTreeSet<String>, info: &BatchInfo) -> Result<bool> {
        if keys.is_empty() {
            return Ok(false);
        }
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        let mut args = vec!["ls-files", "-z", "--"];
        args.extend(&keys);
        let tracked: BTreeSet<String> = split0(&self.git(&args, Some(&[0]), None, None)?.stdout).collect();
        let candidates: Vec<&str> = keys
            .iter()
            .copied()
            .filter(|k| tracked.contains(*k) || self.root.join(k).exists())
            .collect();
        // An untracked key git ignores stays on disk and out of history; a
        // tracked one is committed whatever .gitignore says, as git would.
        let untracked: Vec<&str> = candidates.iter().copied().filter(|k| !tracked.contains(*k)).collect();
        let mut ignored = BTreeSet::new();
        if !untracked.is_empty() {
            let input = untracked.iter().map(|k| format!("{k}\0")).collect::<String>();
            let r = self.run(&["check-ignore", "-z", "--stdin"], &self.root, Some(input.as_bytes()), None)?;
            if r.code > 1 {
                return Err(TransportError::Backend(format!("git check-ignore failed: {}", r.stderr.trim())));
            }
            ignored = split0(&r.stdout).collect();
        }
        let paths: Vec<&str> = candidates.into_iter().filter(|k| !ignored.contains(*k)).collect();
        if paths.is_empty() {
            return Ok(false);
        }
        let mut add = vec!["add", "-A", "--"];
        add.extend(&paths);
        self.git(&add, Some(&[0]), None, None)?;
        let mut diff = vec!["diff", "--cached", "--quiet", "--"];
        diff.extend(&paths);
        if self.git(&diff, Some(&[0, 1]), None, None)?.code == 0 {
            return Ok(false); // wrote what was already committed
        }
        let mut commit = vec!["commit", "-q", "-F", "-", "--"];
        commit.extend(&paths);
        let message = commit_message(info, &paths);
        self.git(&commit, Some(&[0]), Some(message.as_bytes()), None)?;
        self.invalidate();
        Ok(true)
    }

    // --------------------------------------------------------------- sync

    /// Bring in what the remote has: fast-forward, or merge when the two have
    /// diverged. Reports and carries on when it cannot. Returns whether HEAD
    /// moved.
    fn pull(&self) -> Result<bool> {
        let remote = self.remote.clone().unwrap();
        let Some(branch) = self.branch()? else {
            (self.warn)("HEAD is detached, so nothing is pulled or pushed; check out a branch");
            return Ok(false);
        };
        let tracking = format!("refs/remotes/{remote}/{branch}");
        let spec = format!("+refs/heads/{branch}:{tracking}");
        let f = self.git(&["fetch", "--quiet", "--no-tags", &remote, &spec], None, None, Some(NETWORK_TIMEOUT))?;
        if f.code != 0 {
            // A remote with no such branch yet is fine: the first push makes it.
            if !f.stderr.to_lowercase().contains("couldn't find remote ref") {
                (self.warn)(&format!("could not fetch {remote}/{branch}: {}", first_line(&f.stderr).unwrap_or_default()));
            }
            return Ok(false);
        }
        let theirs = self.rev(&tracking)?;
        let ours = self.rev("HEAD")?;
        if theirs.is_empty() || theirs == ours {
            return Ok(false);
        }
        if !ours.is_empty() && self.is_ancestor(&theirs, &ours)? {
            return Ok(false); // only we have moved
        }
        self.invalidate();
        if ours.is_empty() || self.is_ancestor(&ours, &theirs)? {
            let m = self.git(&["merge", "--ff-only", "--quiet", &theirs], None, None, None)?;
            if m.code != 0 {
                (self.warn)(&format!("could not fast-forward to {remote}/{branch}: {}", first_line(&m.stderr).unwrap_or_default()));
            }
            return Ok(m.code == 0);
        }
        let msg = format!("Merge {remote}/{branch}");
        let m = self.git(&["merge", "--no-ff", "--no-edit", "--quiet", "-m", &msg, &theirs], None, None, None)?;
        if m.code == 0 {
            return Ok(true);
        }
        if self.rev("MERGE_HEAD")?.is_empty() {
            // Refused before it started, typically over uncommitted edits it
            // would have overwritten. Nothing to clean up.
            (self.warn)(&format!(
                "could not merge {remote}/{branch}: {}",
                first_line(&m.stderr).or_else(|| first_line(&m.stdout)).unwrap_or_default()
            ));
            return Ok(false);
        }
        let top = self.with_init(|i| i.top.clone());
        let conflicted: Vec<String> = split0(
            &self
                .git_in(&top, &["diff", "--name-only", "-z", "--no-relative", "--diff-filter=U"], Some(&[0]), None, None)?
                .stdout,
        )
        .collect();
        let prefix = self.with_init(|i| i.prefix.clone());
        let derived: Vec<String> = self.derived.iter().map(|d| format!("{prefix}{d}")).collect();
        if !conflicted.is_empty() && conflicted.iter().all(|p| derived.iter().any(|d| p.starts_with(d.as_str()))) {
            // Derived files: keep ours and finish the merge. They are stale
            // against the merged content now, which the vault's reindex repairs.
            for p in &conflicted {
                let c = self.git_in(&top, &["checkout", "--ours", "--", p], None, None, None)?;
                if c.code != 0 {
                    self.git_in(&top, &["rm", "-q", "--", p], Some(&[0]), None, None)?;
                } else {
                    self.git_in(&top, &["add", "--", p], Some(&[0]), None, None)?;
                }
            }
            self.git_in(&top, &["commit", "-q", "--no-edit"], Some(&[0]), None, None)?;
            return Ok(true);
        }
        self.git(&["merge", "--abort"], None, None, None)?;
        let shown: Vec<&str> = conflicted.iter().take(3).map(String::as_str).collect();
        (self.warn)(&format!(
            "{remote}/{branch} and this clone both changed {}{}; merge by hand. Writes stay local until then.",
            shown.join(", "),
            if conflicted.len() > 3 { ", …" } else { "" }
        ));
        Ok(false)
    }

    /// Push; if the remote has moved, pull and try again. Never forces.
    /// Returns true when a merge means the derived keys need rebuilding
    /// before the push is worth retrying.
    fn push(&self) -> Result<bool> {
        let remote = self.remote.clone().unwrap();
        let Some(branch) = self.branch()? else { return Ok(false) };
        let dest = format!("HEAD:refs/heads/{branch}");
        for attempt in 0..PUSH_ATTEMPTS {
            if attempt > 0 {
                // Two clones pushing at once keep beating each other by
                // milliseconds; a little jitter breaks the tie.
                std::thread::sleep(Duration::from_millis(50 * attempt as u64 + jitter(150)));
            }
            let p = self.git(&["push", "--quiet", "--porcelain", &remote, &dest], None, None, Some(NETWORK_TIMEOUT))?;
            if p.code == 0 {
                *self.owe_push.lock().unwrap() = false;
                return Ok(false);
            }
            if !rejected_re().is_match(&format!("{}{}", p.stdout, p.stderr)) {
                (self.warn)(&format!(
                    "could not push to {remote}/{branch}: {}; the commit is kept here and goes with the next push",
                    first_line(&p.stderr).or_else(|| first_line(&p.stdout)).unwrap_or_default()
                ));
                *self.owe_push.lock().unwrap() = true;
                return Ok(false);
            }
            if self.pull()? && !self.derived.is_empty() {
                // The merge brought in content this side's indexes do not
                // cover. The vault rebuilds them in a batch of its own, which
                // pushes again.
                *self.owe_push.lock().unwrap() = true;
                return Ok(true);
            }
        }
        (self.warn)(&format!(
            "{remote}/{branch} kept moving or could not be merged; the commit is kept here and goes with the next push"
        ));
        *self.owe_push.lock().unwrap() = true;
        Ok(false)
    }
}

impl Transport for GitTransport {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.fs.get(key)
    }

    fn list(&self, prefix: &str, opts: &ListOpts) -> Result<Listing> {
        self.fs.list(prefix, opts)
    }

    /// The filesystem's size and etag, with a better mtime: a file whose
    /// content is what HEAD has gets the time of the last commit that
    /// touched it, so "recent" still means something on a fresh clone.
    fn stat(&self, key: &str) -> Result<Option<Stat>> {
        let Some(mut st) = self.fs.stat(key)? else { return Ok(None) };
        if self.ready().is_ok() && self.snapshot().is_ok() {
            let snap = self.snap.lock().unwrap();
            if let Some(s) = snap.as_ref() {
                if s.tracked.contains(key) && !s.dirty.contains(key) {
                    if let Some(t) = s.times.get(key) {
                        st.mtime = Some(t.clone());
                    }
                }
            }
        }
        Ok(Some(st))
    }

    fn put(&self, key: &str, bytes: &[u8], meta: &PutMeta) -> Result<Stat> {
        validate_key(key)?;
        self.write(key, || self.fs.put(key, bytes, meta))
    }

    fn delete(&self, key: &str) -> Result<()> {
        // §1.2: nothing is reported, and a key never there makes no commit.
        self.write(key, || self.fs.delete(key))
    }

    fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.caps
    }

    fn begin_batch(&self) -> Result<()> {
        if self.batch.lock().unwrap().depth > 0 {
            self.batch.lock().unwrap().depth += 1;
            return Ok(());
        }
        self.ready()?;
        let lock = self.take_lock()?;
        if self.remote.is_some() {
            if let Err(e) = self.pull() {
                self.release_lock(&lock);
                return Err(e);
            }
        }
        let mut b = self.batch.lock().unwrap();
        b.depth = 1;
        b.keys.clear();
        b.lock = Some(lock);
        Ok(())
    }

    fn end_batch(&self, info: &BatchInfo) -> Result<BatchEnd> {
        let (keys, lock) = {
            let mut b = self.batch.lock().unwrap();
            if b.depth == 0 {
                return Ok(BatchEnd::default());
            }
            b.depth -= 1;
            if b.depth > 0 {
                return Ok(BatchEnd::default());
            }
            (std::mem::take(&mut b.keys), b.lock.take())
        };
        let finish = || -> Result<BatchEnd> {
            let committed = self
                .commit(&keys, info)
                .map_err(|e| TransportError::Backend(format!("stored on disk but not committed: {e}")))?;
            let mut end = BatchEnd { committed, rederive: false };
            if self.remote.is_some() && (committed || *self.owe_push.lock().unwrap()) {
                end.rederive = self.push()?;
            }
            Ok(end)
        };
        let out = finish();
        if let Some(l) = lock {
            self.release_lock(&l);
        }
        out
    }
}

impl GitTransport {
    /// A put or delete: inside a batch it joins it; outside, it is a batch of
    /// its own. Recorded even when it failed, since it may have changed the
    /// file before failing.
    fn write<T>(&self, key: &str, op: impl FnOnce() -> Result<T>) -> Result<T> {
        let inside = self.batch.lock().unwrap().depth > 0;
        if !inside {
            self.begin_batch()?;
        }
        let r = op();
        self.batch.lock().unwrap().keys.insert(key.to_string());
        self.invalidate();
        if !inside {
            let end = self.end_batch(&BatchInfo::default());
            let v = r?;
            end?;
            return Ok(v);
        }
        r
    }
}

/// Subject, blank line, trailers. Nothing a caller passes can add a line.
fn commit_message(info: &BatchInfo, paths: &[&str]) -> String {
    let one_line = |s: &str| -> String {
        let mapped: String = s
            .chars()
            .map(|c| {
                let n = c as u32;
                if n < 0x20 || (0x7f..=0x9f).contains(&n) || c == '\u{2028}' || c == '\u{2029}' { ' ' } else { c }
            })
            .collect();
        mapped.split(' ').filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ")
    };
    let subject = info.message.clone().filter(|m| !m.trim().is_empty()).unwrap_or_else(|| {
        if paths.len() == 1 {
            format!("Write {}", paths[0])
        } else {
            format!("Write {} objects", paths.len())
        }
    });
    let subject: String = one_line(&subject).chars().take(200).collect();
    let trailers: Vec<String> = info
        .trailers
        .iter()
        .filter(|(k, v)| {
            k.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !one_line(v).is_empty()
        })
        .map(|(k, v)| format!("{k}: {}", one_line(v)))
        .collect();
    if trailers.is_empty() {
        format!("{subject}\n")
    } else {
        format!("{subject}\n\n{}\n", trailers.join("\n"))
    }
}

fn split0(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split('\0').filter(|p| !p.is_empty()).map(str::to_string)
}

fn first_line(s: &str) -> Option<String> {
    let l = s.trim().lines().next()?.trim();
    let l = l.strip_prefix("fatal: ").or_else(|| l.strip_prefix("error: ")).unwrap_or(l);
    (!l.is_empty()).then(|| l.to_string())
}

fn jitter(max: u64) -> u64 {
    rand::random::<u64>() % max.max(1)
}

/// A git ISO 8601 time (`2026-11-08T10:00:00-08:00`) as RFC 3339 UTC.
fn utc(iso: &str) -> String {
    let iso = iso.trim();
    let parse = || -> Option<String> {
        let (date, rest) = iso.split_once('T')?;
        let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
        let (y, m, day) = (d.next()??, d.next()??, d.next()??);
        let (time, off) = if let Some(t) = rest.strip_suffix('Z') {
            (t, 0)
        } else {
            let i = rest.rfind(['+', '-'])?;
            let sign = if &rest[i..i + 1] == "-" { -1 } else { 1 };
            let mut o = rest[i + 1..].split(':').map(|x| x.parse::<i64>().ok());
            (&rest[..i], sign * (o.next()?? * 3600 + o.next().flatten().unwrap_or(0) * 60))
        };
        let mut t = time.split(':').map(|x| x.parse::<i64>().ok());
        let (hh, mm, ss) = (t.next()??, t.next()??, t.next()??);
        // Days from civil, Howard Hinnant's algorithm.
        let y2 = if m <= 2 { y - 1 } else { y };
        let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
        let yoe = y2 - era * 400;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        let secs = days * 86_400 + hh * 3600 + mm * 60 + ss - off;
        Some(crate::transport::fs::rfc3339(secs.max(0) as u64))
    };
    parse().unwrap_or_else(|| iso.to_string())
}

/// Whether a process with this pid exists on this machine.
fn alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if pid == std::process::id() {
        return true;
    }
    #[cfg(unix)]
    {
        // `kill -0` asks without signalling; "not permitted" means it exists.
        match Command::new("kill").arg("-0").arg(pid.to_string()).stderr(Stdio::piped()).output() {
            Ok(o) if o.status.success() => true,
            Ok(o) => String::from_utf8_lossy(&o.stderr).to_lowercase().contains("not permitted"),
            Err(_) => true,
        }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_times_become_utc() {
        assert_eq!(utc("2026-11-08T10:00:00-08:00"), "2026-11-08T18:00:00Z");
        assert_eq!(utc("2026-11-08T10:00:00Z"), "2026-11-08T10:00:00Z");
        assert_eq!(utc("2026-01-01T00:30:00+01:00"), "2025-12-31T23:30:00Z");
    }

    #[test]
    fn a_message_cannot_add_lines() {
        let info = BatchInfo {
            message: Some("Add x\nSigned-off-by: someone".into()),
            trailers: vec![("Basalt-Agent".into(), "a\nb".into()), ("Bad Key".into(), "x".into())],
        };
        assert_eq!(commit_message(&info, &["a"]), "Add x Signed-off-by: someone\n\nBasalt-Agent: a b\n");
    }
}
