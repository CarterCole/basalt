//! The git working-tree transport, PROTOCOL §1 — the same contract the
//! TypeScript reference's git store is held to.
//!
//! Every test makes its own repositories in a temp folder, with git's global
//! and system config shut out, so the result does not depend on whoever runs
//! it. Remotes are bare repositories on disk; nothing touches the network.

mod support;

use basalt::store::{store_object, Provenance, StoreRequest};
use basalt::transport::{BatchInfo, GitTransport, PutMeta, Transport};
use basalt::vault::Vault;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use support::conformance_dir;

/// One identity for every git command in this process, including the ones
/// the transport runs.
fn setup() {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let home = std::env::temp_dir().join(format!("basalt-git-home-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let cfg = home.join("gitconfig");
        std::fs::write(
            &cfg,
            "[user]\n\tname = Basalt Test\n\temail = test@example.com\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n",
        )
        .unwrap();
        std::env::set_var("GIT_CONFIG_GLOBAL", &cfg);
        std::env::set_var("GIT_CONFIG_NOSYSTEM", "1");
        home
    });
}

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> Tmp {
    setup();
    let d = std::env::temp_dir().join(format!("basalt-git-{name}-{}-{}", std::process::id(), basalt::ulid()));
    std::fs::create_dir_all(&d).unwrap();
    Tmp(std::fs::canonicalize(&d).unwrap())
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let o = Command::new("git").args(args).current_dir(cwd).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// A fresh repository holding a committed copy of the minimal vault.
fn repo_with_vault(sub: &str, ignore_index: bool) -> (Tmp, PathBuf) {
    let top = tmp("repo");
    git(&top.0, &["init", "-q"]);
    let root = top.0.join(sub);
    copy_dir(&conformance_dir().join("vaults/minimal/vault"), &root);
    if ignore_index {
        std::fs::write(root.join(".gitignore"), "index/\n").unwrap();
    }
    git(&top.0, &["add", "-A"]);
    git(&top.0, &["commit", "-q", "-m", "Import the vault"]);
    (top, root)
}

type Warnings = Arc<Mutex<Vec<String>>>;

fn open(root: &Path, remote: Option<&str>) -> (Vault, Warnings) {
    let warnings: Warnings = Arc::default();
    let w = Arc::clone(&warnings);
    let t = GitTransport::new(root, remote.map(str::to_string), vec!["index/".into()])
        .with_warn(move |m| w.lock().unwrap().push(m.to_string()));
    t.ready().unwrap();
    let mut v = Vault::open(Box::new(t)).unwrap();
    v.reindex(false).unwrap();
    (v, warnings)
}

fn store(v: &mut Vault, path: &str, text: &str) -> basalt::store::Stored {
    store_object(
        v,
        &StoreRequest { path, bytes: text.as_bytes(), reindex: true, ..Default::default() },
    )
    .unwrap()
}

fn subjects(cwd: &Path, n: usize) -> Vec<String> {
    git(cwd, &["log", &format!("-{n}"), "--format=%s"]).lines().map(str::to_string).collect()
}

fn changed(cwd: &Path, rev: &str) -> Vec<String> {
    let mut v: Vec<String> = git(cwd, &["show", "--format=", "--name-only", rev]).lines().map(str::to_string).collect();
    v.sort();
    v
}

#[test]
fn the_five_operations_round_trip_one_commit_per_write() {
    let (top, root) = repo_with_vault("", false);
    let t = GitTransport::new(&root, None, vec![]);
    t.ready().unwrap();
    t.put("content/Notes/New.md", b"# New\n", &PutMeta::default()).unwrap();
    assert_eq!(t.get("content/Notes/New.md").unwrap().unwrap(), b"# New\n");
    assert!(t.stat("content/Notes/New.md").unwrap().is_some());
    assert!(t.list_all("content/").unwrap().contains(&"content/Notes/New.md".to_string()));
    t.delete("content/Notes/New.md").unwrap();
    assert!(t.get("content/Notes/New.md").unwrap().is_none());
    // A delete of a key that was never there commits nothing.
    t.delete("content/Notes/Never.md").unwrap();
    assert_eq!(subjects(&top.0, 3), ["Write content/Notes/New.md", "Write content/Notes/New.md", "Import the vault"]);
    assert_eq!(git(&top.0, &["status", "--porcelain"]), "");
}

#[test]
fn conditional_put_still_turns_a_lost_update_into_a_conflict() {
    let (_top, root) = repo_with_vault("", false);
    let t = GitTransport::new(&root, None, vec![]);
    let err = t
        .put("content/Notes/Hexes.md", b"x", &PutMeta { content_type: None, if_match: Some(None) })
        .unwrap_err();
    assert!(matches!(err, basalt::transport::TransportError::PreconditionFailed(_)));
}

#[test]
fn a_vault_in_a_subfolder_indexes_as_the_corpus_expects() {
    let (_top, root) = repo_with_vault("vaults/mine", false);
    let (v, _) = open(&root, None);
    let want = std::fs::read_to_string(conformance_dir().join("vaults/minimal/expected/nodes.json")).unwrap();
    let want = basalt::canonical::parse_json(&want).unwrap().comparable();
    let got = v.indexes.as_ref().unwrap().nodes.comparable();
    assert_eq!(got.to_canonical_string(), want.to_canonical_string());
}

#[test]
fn paths_are_literal_never_globs() {
    let (top, root) = repo_with_vault("", false);
    std::fs::write(root.join("content/Notes/draft-1.md"), "# untouched\n").unwrap();
    let (mut v, _) = open(&root, None);
    store(&mut v, "Notes/[draft] *.md", "# glob?\n");
    assert_eq!(changed(&top.0, "HEAD").iter().filter(|p| p.contains("draft-1")).count(), 0);
    assert!(git(&top.0, &["status", "--porcelain"]).contains("draft-1.md"));
}

#[test]
fn a_stored_note_its_indexes_and_its_provenance_are_one_commit() {
    let (top, root) = repo_with_vault("", false);
    let (mut v, _) = open(&root, None);
    let prov = Provenance { agent: Some("claude-code".into()), account: Some("work".into()), ..Default::default() };
    store_object(
        &mut v,
        &StoreRequest {
            principal: Some("u:editor"),
            path: "Notes/Idea.md",
            bytes: b"# Idea\n",
            provenance: Some(&prov),
            reindex: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(subjects(&top.0, 1), ["Add Notes/Idea.md"]);
    let files = changed(&top.0, "HEAD");
    assert!(files.contains(&"content/Notes/Idea.md".to_string()), "{files:?}");
    assert!(files.contains(&"index/nodes.json".to_string()), "{files:?}");
    let body = git(&top.0, &["log", "-1", "--format=%B"]);
    for t in ["Basalt-Principal: u:editor", "Basalt-Agent: claude-code", "Basalt-Account: work"] {
        assert!(body.contains(t), "{body}");
    }
    assert_eq!(git(&top.0, &["log", "-1", "--format=%an <%ae>"]), "Basalt Test <test@example.com>");
    assert_eq!(git(&top.0, &["status", "--porcelain"]), "");
}

#[test]
fn an_asset_and_its_sidecar_are_one_commit_too() {
    let (top, root) = repo_with_vault("", false);
    let (mut v, _) = open(&root, None);
    store_object(&mut v, &StoreRequest { path: "Assets/x.png", bytes: &[0x89, 0x50], reindex: true, ..Default::default() }).unwrap();
    let files = changed(&top.0, "HEAD");
    assert!(files.contains(&"content/Assets/x.png".to_string()));
    assert!(files.contains(&"meta/folders/Assets/entries.yaml".to_string()));
    assert_eq!(subjects(&top.0, 2), ["Add Assets/x.png", "Import the vault"]);
}

#[test]
fn what_you_have_staged_or_are_editing_is_left_alone() {
    let (top, root) = repo_with_vault("", false);
    let hexes = root.join("content/Notes/Hexes.md");
    std::fs::write(&hexes, format!("{}\nhalf-done\n", std::fs::read_to_string(&hexes).unwrap())).unwrap();
    std::fs::write(root.join("content/Notes/Staged.md"), "# staged\n").unwrap();
    git(&top.0, &["add", "content/Notes/Staged.md"]);
    let (mut v, _) = open(&root, None);
    store(&mut v, "Notes/Mine.md", "# mine\n");
    let files = changed(&top.0, "HEAD");
    assert!(!files.iter().any(|f| f.contains("Hexes") || f.contains("Staged")), "{files:?}");
    let status = git(&top.0, &["status", "--porcelain"]);
    assert!(status.lines().any(|l| l.trim_start() == "M content/Notes/Hexes.md"), "{status}");
    assert!(status.contains("A  content/Notes/Staged.md"), "{status}");
}

#[test]
fn a_key_gitignore_excludes_is_stored_but_not_committed() {
    let (top, root) = repo_with_vault("", true);
    let (mut v, _) = open(&root, None);
    store(&mut v, "Notes/Idea.md", "# Idea\n");
    assert!(root.join("index/nodes.json").exists());
    let files = changed(&top.0, "HEAD");
    assert_eq!(files, ["content/Notes/Idea.md"]);
}

#[test]
fn reindex_and_mint_are_a_commit_each_and_only_when_something_changed() {
    let (top, root) = repo_with_vault("", false);
    let (mut v, _) = open(&root, None);
    v.reindex(true).unwrap();
    let after_first = subjects(&top.0, 1);
    v.reindex(true).unwrap();
    assert_eq!(subjects(&top.0, 1), after_first, "a reindex that changes nothing makes no commit");
    std::fs::write(root.join("content/Notes/Unbound.md"), "# no id\n").unwrap();
    let minted = v.mint_ids().unwrap();
    assert_eq!(minted.len(), 1);
    assert_eq!(subjects(&top.0, 1), ["Mint ids for 1 object"]);
    assert!(v.mint_ids().unwrap().is_empty());
    assert_eq!(subjects(&top.0, 1), ["Mint ids for 1 object"]);
}

#[test]
fn mtime_is_the_last_commit_that_touched_a_file() {
    let (top, root) = repo_with_vault("", false);
    let when = "2001-02-03T04:05:06Z";
    std::fs::write(root.join("content/Notes/Old.md"), "# old\n").unwrap();
    git(&top.0, &["add", "-A"]);
    let o = Command::new("git")
        .args(["commit", "-qm", "old"])
        .env("GIT_COMMITTER_DATE", when)
        .env("GIT_AUTHOR_DATE", when)
        .current_dir(&top.0)
        .output()
        .unwrap();
    assert!(o.status.success());
    let t = GitTransport::new(&root, None, vec![]);
    t.ready().unwrap();
    assert_eq!(t.stat("content/Notes/Old.md").unwrap().unwrap().mtime.as_deref(), Some(when));
    // Modified since: the filesystem's time, not the commit's.
    std::fs::write(root.join("content/Notes/Old.md"), "# changed\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_ne!(t.stat("content/Notes/Old.md").unwrap().unwrap().mtime.as_deref(), Some(when));
}

#[test]
fn a_folder_outside_a_repository_or_a_bare_one_is_refused_plainly() {
    let plain = tmp("plain");
    let e = GitTransport::new(&plain.0, None, vec![]).ready().unwrap_err().to_string();
    assert!(e.contains("not in a git repository"), "{e}");
    let bare = tmp("bare");
    git(&bare.0, &["init", "-q", "--bare"]);
    let e = GitTransport::new(&bare.0, None, vec![]).ready().unwrap_err().to_string();
    assert!(e.contains("bare repository"), "{e}");
}

/// A bare remote and `n` clones of it, each holding the vault.
fn remote_and_clones(n: usize) -> (Tmp, Vec<Tmp>) {
    let (top, _) = repo_with_vault("", false);
    let remote = tmp("remote");
    git(&remote.0, &["clone", "-q", "--bare", top.0.to_str().unwrap(), "."]);
    let clones = (0..n)
        .map(|_| {
            let c = tmp("clone");
            git(&c.0, &["clone", "-q", remote.0.to_str().unwrap(), "."]);
            c
        })
        .collect();
    (remote, clones)
}

#[test]
fn two_clones_writing_through_one_remote_both_land_with_fresh_indexes() {
    let (remote, clones) = remote_and_clones(2);
    let (a, b) = (&clones[0].0, &clones[1].0);
    // B writes while it cannot reach the remote: its commit is local only.
    let (mut offline, _) = open(b, None);
    store(&mut offline, "Notes/From B offline.md", "# B0\n");
    drop(offline);

    let (mut va, wa) = open(a, Some("origin"));
    store(&mut va, "Notes/From A.md", "# A\n");
    assert!(wa.lock().unwrap().is_empty(), "{:?}", wa.lock().unwrap());

    // Now B, syncing: the histories diverged and both rewrote index/*.json.
    // Those are derived, so the merge keeps B's and the reindex settles them.
    let (mut vb, wb) = open(b, Some("origin"));
    store(&mut vb, "Notes/From B.md", "# B1\n");
    assert!(wb.lock().unwrap().is_empty(), "{:?}", wb.lock().unwrap());

    let check = tmp("check");
    git(&check.0, &["clone", "-q", remote.0.to_str().unwrap(), "."]);
    for name in ["From A", "From B offline", "From B"] {
        assert!(check.0.join(format!("content/Notes/{name}.md")).exists(), "{name} missing on the remote");
    }
    let (fresh, _) = open(&check.0, None);
    let stored = basalt::canonical::parse_json(&std::fs::read_to_string(check.0.join("index/nodes.json")).unwrap()).unwrap();
    assert_eq!(
        stored.get("source_digest").and_then(|d| d.as_str()),
        Some(fresh.indexes.as_ref().unwrap().source_digest.as_str()),
        "the indexes on the remote are not stale"
    );
    assert_eq!(git(b, &["status", "--porcelain"]), "");
}

#[test]
fn a_real_conflict_is_aborted_and_reported_and_the_write_still_succeeds() {
    let (remote, clones) = remote_and_clones(2);
    let (a, b) = (&clones[0].0, &clones[1].0);
    let edit = |dir: &Path, line: &str| {
        let p = dir.join("content/Notes/Columns.md");
        std::fs::write(&p, format!("{}\n{line}\n", std::fs::read_to_string(&p).unwrap())).unwrap();
        git(dir, &["commit", "-q", "-am", line]);
    };
    edit(a, "from A");
    git(a, &["push", "-q", "origin", "main"]);
    edit(b, "from B");

    let (mut vb, wb) = open(b, Some("origin"));
    store(&mut vb, "Notes/Safe.md", "# Safe\n");
    let w = wb.lock().unwrap().join("\n");
    assert!(w.contains("both changed content/Notes/Columns.md") && w.contains("merge by hand"), "{w}");
    assert!(b.join("content/Notes/Safe.md").exists());
    assert_eq!(subjects(b, 1), ["Add Notes/Safe.md"]);
    assert!(!b.join(".git/MERGE_HEAD").exists(), "the merge was not left half-done");
    assert_eq!(git(b, &["status", "--porcelain"]), "");
    assert_eq!(git(&remote.0, &["log", "-1", "--format=%s", "main"]), "from A", "nothing was forced");
}

#[test]
fn an_unreachable_remote_is_a_warning_not_a_failed_write() {
    let (_remote, clones) = remote_and_clones(1);
    let a = &clones[0].0;
    git(a, &["remote", "set-url", "origin", a.join("no-such-remote.git").to_str().unwrap()]);
    let (mut va, wa) = open(a, Some("origin"));
    store(&mut va, "Notes/Local.md", "# Local\n");
    assert_eq!(subjects(a, 1), ["Add Notes/Local.md"]);
    let w = wa.lock().unwrap().join("\n");
    assert!(w.contains("could not fetch"), "{w}");
    assert!(w.contains("could not push") && w.contains("next push"), "{w}");
}

#[test]
fn remote_must_name_a_remote_that_exists() {
    let (_remote, clones) = remote_and_clones(1);
    let e = GitTransport::new(&clones[0].0, Some("upstream".into()), vec![]).ready().unwrap_err().to_string();
    assert!(e.contains("no remote named upstream"), "{e}");
}

#[test]
fn a_push_that_has_to_merge_first_rebuilds_the_indexes_before_it_goes_out() {
    let (remote, clones) = remote_and_clones(2);
    let (a, b) = (&clones[0].0, &clones[1].0);
    let (mut va, wa) = open(a, Some("origin"));
    let (mut vb, wb) = open(b, Some("origin"));
    // A pushes while B is mid-write, after B's own pull: B's push is
    // rejected, B merges, and the indexes it pushes must cover A's note too.
    vb.transport.begin_batch().unwrap();
    vb.transport.put("content/Notes/From B.md", b"# B\n", &PutMeta::default()).unwrap();
    store(&mut va, "Notes/From A.md", "# A\n");
    vb.reindex(true).unwrap();
    vb.finish_batch(&BatchInfo::message("B writes")).unwrap();
    let all: Vec<String> = wa.lock().unwrap().iter().chain(wb.lock().unwrap().iter()).cloned().collect();
    assert!(all.is_empty(), "{all:?}");
    assert_eq!(subjects(b, 1), ["Rebuild indexes after merging"]);

    let check = tmp("check");
    git(&check.0, &["clone", "-q", remote.0.to_str().unwrap(), "."]);
    let (fresh, _) = open(&check.0, None);
    let text = std::fs::read_to_string(check.0.join("index/nodes.json")).unwrap();
    let stored = basalt::canonical::parse_json(&text).unwrap();
    assert_eq!(
        stored.get("source_digest").and_then(|d| d.as_str()),
        Some(fresh.indexes.as_ref().unwrap().source_digest.as_str()),
        "pushed indexes are stale"
    );
    assert!(text.contains("Notes/From A.md") && text.contains("Notes/From B.md"));
}

#[test]
fn writers_in_several_processes_take_turns_and_a_dead_ones_lock_is_taken_over() {
    let (top, root) = repo_with_vault("", false);
    // A lock left by a process that no longer exists.
    let lock = top.0.join(".git/basalt-write.lock");
    std::fs::write(&lock, "999999 2026-01-01T00:00:00Z\n").unwrap();
    let src = tmp("src");
    let runs: Vec<_> = (0..4)
        .map(|i| {
            let f = src.0.join(format!("Turn {i}.md"));
            std::fs::write(&f, format!("# Turn {i}\n")).unwrap();
            Command::new(env!("CARGO_BIN_EXE_basalt"))
                .args(["add", f.to_str().unwrap(), "--git", root.to_str().unwrap(), "--to", "Notes/"])
                .env("NO_COLOR", "1")
                .output()
        })
        .collect();
    for r in runs {
        let o = r.unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success() && !text.contains("refused") && !text.contains("basalt:"), "{text}");
    }
    let adds = subjects(&top.0, 20).into_iter().filter(|s| s.starts_with("Add Notes/Turn")).count();
    assert_eq!(adds, 4);
    assert_eq!(git(&top.0, &["status", "--porcelain"]), "");
    assert!(!lock.exists(), "the lock is released");
}
