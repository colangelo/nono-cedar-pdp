//! Trust checks on the daemon's own state paths: the hot-reloaded policy
//! directory and the audit log. [`check`] runs once at startup; its refusal core,
//! [`refuse_untrusted_policy_dir`], re-runs in the watcher before every reloaded
//! policy set is adopted.
//!
//! Why they need checking at all: write access to the policy directory *is* write
//! access to every future decision. Dropping `permit (principal, action,
//! resource);` into any `*.cedar` file there is adopted after the watcher's ~150 ms
//! debounce, with nothing but an INFO line. Write access to the audit log is write
//! access to the record of what was decided, which is the compensating control for
//! an unauthenticated webhook.
//!
//! The refusal covers the **ancestor chain** too, because the mode of the policy
//! directory itself never mattered if a parent is loose: whoever can write an
//! ancestor renames the directory out from under the daemon and substitutes their
//! own. The walk runs over the absolutized (symlink-resolved) path, parent up to
//! root, existing components only, and refuses on a group- or world-writable
//! ancestor **without the sticky bit**. Sticky exempts an *ancestor* — it blocks
//! renaming or unlinking entries owned by someone else, which is precisely the
//! ancestor attack, so `/tmp`-style `1777` chains stay usable — but it never
//! exempts the policy directory itself, where the attack is *creating* a new
//! `*.cedar` file and sticky does not restrict creation. Like every check in this
//! module, the walk defends against other local users only; it says nothing about
//! the sandboxed agent (point 1 below).
//!
//! **Both checks here are much weaker than they look, and being precise about that
//! is the point of this module.**
//!
//! 1. **The refusal (group- or world-writable) does nothing about the sandboxed
//!    agent.** nono's sandboxes are path-based — Seatbelt on macOS, Landlock on
//!    Linux — and neither changes uid, so an agent nono launches runs as the *same
//!    user* as this daemon. Owner-write is precisely the access it has, and no mode
//!    this process could set would take it away. What the refusal buys is a
//!    different and weaker threat: another local user — a shared group, a service
//!    account, anyone at all under `o+w` — who could otherwise add or rewrite a
//!    policy. Worth refusing over, but it is not the sandbox-escape defence.
//! 2. **The cwd warning is a heuristic proxy, and it is wrong in both
//!    directions.** It cannot read the nono profile, so it *misses* an absolute
//!    `policy_dir` that happens to sit inside a granted tree — on macOS the default
//!    profile groups grant write to `/tmp`, `/private/tmp`, `$TMPDIR` and
//!    `/var/folders`, so a policy directory under any temp path is agent-writable
//!    while this check stays quiet — and it *fires* on a plain development run
//!    where no agent exists at all.
//!
//! The only control that actually stops a sandboxed agent from rewriting the
//! policies that govern it is **the nono profile not granting write access to these
//! paths**. README "Keep the policy directory out of the sandbox" has the procedure
//! for checking a profile against that rule.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    #[error(
        "{what} {path} is {who}-writable (mode {mode}) — another local user could add or \
         rewrite a policy and decide this daemon's approvals, so it refuses to serve. Fix with \
         `chmod go-w {path}` (a user-private group counts: this process cannot tell one from a \
         shared group). This says nothing about a sandboxed agent, which runs as the same user \
         as this daemon and is bounded only by its nono profile's write grants"
    )]
    Writable {
        what: &'static str,
        path: PathBuf,
        mode: String,
        who: String,
    },
    #[error(
        "{what} {path} has a {who}-writable non-sticky ancestor {ancestor} (mode {mode}) — \
         another local user could rename entries in that ancestor and substitute the whole \
         tree below it, redirecting what this daemon reads and writes there no matter how \
         tight the {what}'s own mode is, so it refuses to serve. Fix with `chmod go-w \
         {ancestor}`, or set the sticky bit (`chmod +t {ancestor}`) if the directory is \
         deliberately shared: sticky stops others renaming or unlinking entries they do not \
         own, which is why /tmp-style 1777 directories are exempt here (and why sticky does \
         not exempt the policy directory itself, where creating a new *.cedar file is the \
         attack). This says nothing about a sandboxed agent, which runs as the same user as \
         this daemon and is bounded only by its nono profile's write grants"
    )]
    WritableAncestor {
        what: &'static str,
        path: PathBuf,
        ancestor: PathBuf,
        mode: String,
        who: String,
    },
    #[error(
        "checking {path}: {source} — refusing to serve without knowing who can write the \
         policies"
    )]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Check the paths the daemon's own trust boundary rests on.
///
/// `Err` means **do not serve**. `Ok` carries advisory warnings for the caller to
/// log; see the module docs for what each one is and is not worth.
///
/// `cwd` is passed in rather than read from the process so it can be tested, and is
/// `None` when the process has no readable working directory (then the containment
/// warnings are simply not computed — a missing cwd is not a reason to refuse a
/// deployment whose paths are absolute).
pub fn check(
    policy_dir: &Path,
    audit_log: &Path,
    cwd: Option<&Path>,
) -> Result<Vec<String>, IsolationError> {
    let base = cwd.map(|c| absolutize(c, None));
    let policy_dir = absolutize(policy_dir, base.as_deref());
    let audit_log = absolutize(audit_log, base.as_deref());

    refuse_untrusted_policy_dir(&policy_dir)?;
    refuse_on_loose_ancestors("audit log", &audit_log)?;

    let mut warnings = Vec::new();
    if let Some(base) = base {
        if policy_dir.starts_with(&base) {
            warnings.push(policy_dir_inside_cwd(&policy_dir, &base));
        }
        if audit_log.starts_with(&base) {
            warnings.push(audit_log_inside_cwd(&audit_log, &base));
        }
    }
    Ok(warnings)
}

/// The refusal core for the policy directory: the directory itself, every policy
/// file the loader would load, and the existing ancestor chain.
///
/// One implementation, two callers (D5): [`check`] at startup, and the watcher
/// before every reload — so the startup path and the reload path cannot drift
/// apart. No cwd warnings here: those are advisory posture messages, and repeating
/// them on every debounce would train operators to filter ERROR-adjacent output.
/// Like everything in this module, an `Err` defends against other local users; it
/// says nothing about the sandboxed agent, which runs as the same user as this
/// daemon.
pub(crate) fn refuse_untrusted_policy_dir(policy_dir: &Path) -> Result<(), IsolationError> {
    // Absolutize so the ancestor walk runs over the real, symlink-resolved chain.
    // Idempotent for the already-absolutized path `check` passes; the watcher
    // hands over the configured (possibly repo-relative) path as-is.
    let policy_dir = absolutize(policy_dir, None);
    refuse_if_loosely_writable("policy directory", &policy_dir)?;
    // Every file the loader would actually load. A `.cedar` name it skips — an
    // editor's lock file or backup — decides nothing, and refusing over one would
    // stop the daemon for as long as a policy file is open in an editor.
    let entries = std::fs::read_dir(&policy_dir).map_err(|source| IsolationError::Io {
        path: policy_dir.clone(),
        source,
    })?;
    for entry in entries {
        let path = entry
            .map_err(|source| IsolationError::Io {
                path: policy_dir.clone(),
                source,
            })?
            .path();
        if !path.extension().is_some_and(|e| e == "cedar") {
            continue;
        }
        if !crate::cedar::engine::is_loadable_policy_file(&path) {
            continue;
        }
        // Follows symlinks on purpose: the loader reads through them, so the mode
        // that decides who can change a policy is the target's.
        refuse_if_loosely_writable("policy file", &path)?;
    }
    refuse_on_loose_ancestors("policy directory", &policy_dir)
}

fn refuse_if_loosely_writable(what: &'static str, path: &Path) -> Result<(), IsolationError> {
    let metadata = std::fs::metadata(path).map_err(|source| IsolationError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o7777;
    if let Some(who) = loose_writers(mode) {
        return Err(IsolationError::Writable {
            what,
            path: path.to_path_buf(),
            mode: format!("{mode:04o}"),
            who: who.to_string(),
        });
    }
    Ok(())
}

/// Walk every existing ancestor of `path` — its parent up to the root — and refuse
/// on one that is group- or world-writable without the sticky bit.
///
/// `path` is already absolutized, so the chain being walked is the real one, not a
/// lexical guess through symlinks. An ancestor that does not exist yet (the audit
/// log's directory before the first record) cannot have its entries renamed by
/// anyone and is skipped; an ancestor that exists but cannot be inspected is a
/// refusal — an unknown mode has to count as a loose one, or the walk is exactly as
/// good as not having one.
fn refuse_on_loose_ancestors(what: &'static str, path: &Path) -> Result<(), IsolationError> {
    let mut current = path.parent();
    while let Some(ancestor) = current {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match std::fs::metadata(ancestor) {
            // Only a directory can host the rename. Mode bits on a file or device
            // ancestor (`/dev/null/decisions.jsonl` is the config typo that hits
            // this) grant no power over directory entries, and nothing below one
            // can ever exist — the audit log's own open fails with an honest "not
            // a directory" instead of a rename warning that cannot apply.
            Ok(metadata) if metadata.is_dir() => {
                let mode = metadata.permissions().mode() & 0o7777;
                if let Some(who) = loose_ancestor_writers(mode) {
                    return Err(IsolationError::WritableAncestor {
                        what,
                        path: path.to_path_buf(),
                        ancestor: ancestor.to_path_buf(),
                        mode: format!("{mode:04o}"),
                        who: who.to_string(),
                    });
                }
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(IsolationError::Io {
                    path: ancestor.to_path_buf(),
                    source,
                });
            }
        }
        current = ancestor.parent();
    }
    Ok(())
}

/// Like [`loose_writers`], but for an *ancestor*, where the sticky bit IS a
/// mitigation. Two different attacks, two different truth tables: on the policy
/// directory itself the attack is *creating* a new `*.cedar` file — a new file is a
/// new policy, and sticky does not restrict creation. On an ancestor the attack is
/// *renaming* our component out from under the daemon and substituting another
/// tree, which is exactly what sticky blocks (only the entry's owner, or the
/// directory's, may rename or unlink it). Creating a sibling does not help the
/// attacker here: our component's name is already taken. Without this exemption
/// every path below `/tmp` (mode `1777`) would refuse, a false positive that
/// breeds override flags.
fn loose_ancestor_writers(mode: u32) -> Option<&'static str> {
    if mode & 0o1000 != 0 {
        return None;
    }
    loose_writers(mode)
}

/// Who besides the owner may write, if anyone. The sticky bit is deliberately not
/// a mitigation: `/tmp`-style modes still let anyone *create* a new `*.cedar` file,
/// and a new file is a new policy.
fn loose_writers(mode: u32) -> Option<&'static str> {
    match (mode & 0o020 != 0, mode & 0o002 != 0) {
        (true, true) => Some("group- and world"),
        (true, false) => Some("group"),
        (false, true) => Some("world"),
        (false, false) => None,
    }
}

fn policy_dir_inside_cwd(policy_dir: &Path, cwd: &Path) -> String {
    format!(
        "SECURITY: the policy directory {dir} is inside the current working directory {cwd}. \
         If a nono profile grants a sandboxed agent write access to this tree — \
         `workdir.access: \"readwrite\"`, `nono run --allow-cwd`, a `filesystem.allow`/`write` \
         entry, or a `command_policies.commands.*.from.*.sandbox.fs_write` grant — then the \
         agent can drop `permit (principal, action, resource);` into a *.cedar file here and \
         this daemon adopts it within the ~150 ms watch debounce, i.e. it decides its own \
         approvals. File modes cannot prevent that: nono's sandboxes are path-based \
         (Seatbelt/Landlock) and do not change uid, so the agent runs as the same user as this \
         daemon. Treat this as a development shortcut only; a deployment points policy_dir at a \
         path no profile grants write access to (shipped default: \
         ~/.config/nono-cedar-pdp/policies). This check is only a proxy for that rule: it \
         cannot read your profile, so it also fires when no agent is involved, and it stays \
         silent for a policy directory outside the cwd that a profile does grant — on macOS the \
         default groups grant write to /tmp, $TMPDIR and /var/folders. Check the real thing \
         with: nono profile show <profile> --format manifest | jq -r \
         '.filesystem.grants[] | select(.access | test(\"write\")) | .path'",
        dir = policy_dir.display(),
        cwd = cwd.display(),
    )
}

fn audit_log_inside_cwd(audit_log: &Path, cwd: &Path) -> String {
    format!(
        "SECURITY: the audit log {log} is inside the current working directory {cwd}. The audit \
         trail is the compensating control for an unauthenticated webhook, so an agent granted \
         write access to this tree can truncate or forge the record of what was decided — and \
         file modes cannot prevent it, since the sandbox runs as the same user as this daemon. \
         A deployment points audit_log at a path no profile grants write access to (shipped \
         default: ~/.local/state/nono-cedar-pdp/decisions.jsonl)",
        log = audit_log.display(),
        cwd = cwd.display(),
    )
}

/// Absolute, symlink-resolved form of `path`, resolving as much of it as exists.
///
/// A path that does not exist yet — the audit log before its first record — still
/// has to be comparable with the working directory, and on macOS the comparison is
/// wrong unless the existing part is resolved: `/var` is a symlink to
/// `/private/var`, and `/tmp` to `/private/tmp`.
fn absolutize(path: &Path, cwd: Option<&Path>) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match cwd {
            Some(cwd) => cwd.join(path),
            None => match std::env::current_dir() {
                Ok(cwd) => cwd.join(path),
                Err(_) => path.to_path_buf(),
            },
        }
    };

    let mut prefix = joined.clone();
    let mut rest: Vec<OsString> = Vec::new();
    loop {
        if let Ok(resolved) = std::fs::canonicalize(&prefix) {
            let mut out = resolved;
            for component in rest.iter().rev() {
                out.push(component);
            }
            return out;
        }
        match (prefix.file_name(), prefix.parent()) {
            (Some(name), Some(parent)) if !parent.as_os_str().is_empty() => {
                rest.push(name.to_os_string());
                prefix = parent.to_path_buf();
            }
            // Nothing left to resolve (a root, or a bare relative name with no
            // readable cwd): the lexical answer is the best available.
            _ => return joined,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// A policy directory with one loadable policy in it, both owner-only.
    fn policy_dir(root: &Path) -> PathBuf {
        let dir = root.join("policies");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("00-baseline.cedar"),
            "forbid (principal, action, resource);",
        )
        .unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            dir.join("00-baseline.cedar"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        dir
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The whole set of policies is what decides every approval, so a directory a
    /// second local user can add a file to is a directory in which someone else
    /// can write `permit (principal, action, resource);`.
    #[test]
    fn a_group_writable_policy_directory_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        chmod(&dir, 0o770);

        let err = check(&dir, &root.path().join("decisions.jsonl"), None).unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, IsolationError::Writable { .. }),
            "want a refusal, got {text}"
        );
        assert!(text.contains("group"), "{text}");
        assert!(text.contains("0770"), "the mode must be named: {text}");
        assert!(
            text.contains(&dir.display().to_string()),
            "the path must be named: {text}"
        );
        assert!(
            text.contains("chmod go-w"),
            "the operator needs the remedy: {text}"
        );
    }

    #[test]
    fn a_world_writable_policy_directory_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        chmod(&dir, 0o707);

        let err = check(&dir, &root.path().join("decisions.jsonl"), None).unwrap_err();
        assert!(matches!(err, IsolationError::Writable { .. }), "{err}");
        assert!(err.to_string().contains("world"), "{err}");
    }

    /// An owner-only directory is not enough: a single loose *file* in it is a
    /// policy someone else can rewrite in place.
    #[test]
    fn a_group_writable_policy_file_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        chmod(&dir.join("00-baseline.cedar"), 0o660);

        let err = check(&dir, &root.path().join("decisions.jsonl"), None).unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, IsolationError::Writable { .. }), "{text}");
        assert!(text.contains("00-baseline.cedar"), "{text}");
    }

    /// A `.cedar` name the loader skips — an editor's lock file or backup — is
    /// never part of a decision, so its mode is not a reason to refuse to serve.
    /// Refusing on one would stop the daemon for as long as a file is open in an
    /// editor.
    #[test]
    fn a_loose_file_the_loader_ignores_is_not_a_refusal() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        for ignored in [".00-baseline.cedar", "#00-baseline.cedar#", "notes.txt"] {
            std::fs::write(dir.join(ignored), "whatever").unwrap();
            chmod(&dir.join(ignored), 0o666);
        }

        let warnings = check(&dir, &root.path().join("decisions.jsonl"), None)
            .unwrap_or_else(|e| panic!("a file the loader ignores must not refuse: {e}"));
        assert!(warnings.is_empty(), "{warnings:#?}");
    }

    /// A policy file that is a symlink is only as safe as its target: the loader
    /// follows it, so the mode that matters is the target's.
    #[test]
    fn a_policy_symlinked_to_a_world_writable_file_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        let target = root.path().join("shared.cedar");
        std::fs::write(&target, "forbid (principal, action, resource);").unwrap();
        chmod(&target, 0o666);
        std::os::unix::fs::symlink(&target, dir.join("99-linked.cedar")).unwrap();

        let err = check(&dir, &root.path().join("decisions.jsonl"), None).unwrap_err();
        assert!(matches!(err, IsolationError::Writable { .. }), "{err}");
    }

    /// Fail closed: if we cannot tell who can write the policies, we do not serve.
    #[test]
    fn a_policy_directory_we_cannot_stat_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("nowhere");

        let err = check(&missing, &root.path().join("decisions.jsonl"), None).unwrap_err();
        assert!(matches!(err, IsolationError::Io { .. }), "{err}");
        assert!(err.to_string().contains("nowhere"), "{err}");
    }

    /// The mode of the policy directory itself never mattered if an ancestor is
    /// loose: another local user who can write the *parent* renames the directory
    /// out from under the daemon and substitutes their own. The refusal must name
    /// the ancestor — the operator would otherwise stare at a `0700` policy dir
    /// wondering what to fix.
    #[test]
    fn a_loose_non_sticky_ancestor_of_the_policy_dir_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("shared");
        std::fs::create_dir(&parent).unwrap();
        let dir = policy_dir(&parent);
        chmod(&parent, 0o770);

        let err = check(&dir, &root.path().join("decisions.jsonl"), None).unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, IsolationError::WritableAncestor { .. }),
            "want an ancestor refusal, got {text}"
        );
        assert!(
            text.contains(&parent.display().to_string()),
            "the ancestor must be named, not the policy dir: {text}"
        );
        assert!(text.contains("0770"), "the mode must be named: {text}");
        assert!(text.contains("group"), "{text}");
        assert!(
            text.contains("sticky"),
            "the operator needs the sticky rationale to understand why /tmp is fine \
             and this is not: {text}"
        );
        assert!(
            text.contains("chmod go-w"),
            "the operator needs the remedy: {text}"
        );
        assert!(
            text.contains("same user"),
            "the refusal must not overstate itself — it defends against other local \
             users, not the sandboxed agent: {text}"
        );
    }

    /// The sticky bit blocks exactly the ancestor attack — renaming or unlinking an
    /// entry owned by someone else — so a `/tmp`-style `1777` ancestor is not a
    /// refusal. (It stays a refusal on the policy directory itself, where the attack
    /// is *creating* a new `*.cedar` file and sticky does not restrict creation.)
    /// Every test in this suite already runs under `/private/var/folders/...`, so a
    /// false positive here would also brick the fixtures.
    #[test]
    fn a_sticky_world_writable_ancestor_is_not_a_refusal() {
        let root = tempfile::tempdir().unwrap();
        let shared = root.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let dir = policy_dir(&shared);
        chmod(&shared, 0o1777);

        let warnings = check(&dir, &root.path().join("decisions.jsonl"), None)
            .unwrap_or_else(|e| panic!("a sticky ancestor must not refuse: {e}"));
        assert!(warnings.is_empty(), "{warnings:#?}");
    }

    /// The audit log's chain matters for the same reason the policy dir's does: a
    /// substituted audit directory silently redirects the record of what was
    /// decided, which is the compensating control for an unauthenticated webhook.
    #[test]
    fn a_loose_non_sticky_ancestor_of_the_audit_log_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        let logs = root.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        chmod(&logs, 0o707);

        let err = check(&dir, &logs.join("decisions.jsonl"), None).unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, IsolationError::WritableAncestor { .. }),
            "want an ancestor refusal, got {text}"
        );
        assert!(
            text.contains("audit log"),
            "the message must say which state path is at stake: {text}"
        );
        assert!(
            text.contains(&logs.display().to_string()),
            "the ancestor must be named: {text}"
        );
        assert!(text.contains("0707"), "{text}");
        assert!(text.contains("world"), "{text}");
    }

    /// A non-directory ancestor is not the walk's business: mode bits on a file or
    /// device grant no power over directory entries, so there is no rename attack
    /// through it — and nothing below it can ever exist, so the path fails later at
    /// the audit log's own open with an honest "not a directory". The daemon still
    /// refuses to serve either way; what this pins is *which* error the operator
    /// reads (the real fixture is `/dev/null/decisions.jsonl`, whose `0666` is a
    /// device's, not a loose directory's).
    #[test]
    fn a_world_writable_non_directory_ancestor_is_not_the_walks_refusal() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        let blocker = root.path().join("blocker.txt");
        std::fs::write(&blocker, "not a directory").unwrap();
        chmod(&blocker, 0o666);

        let warnings = check(&dir, &blocker.join("decisions.jsonl"), None)
            .unwrap_or_else(|e| panic!("a file ancestor is the open's error, not the walk's: {e}"));
        assert!(warnings.is_empty(), "{warnings:#?}");
    }

    /// Fail closed on the walk too: an ancestor that cannot be stat'ed is an
    /// ancestor whose writers are unknown, and skipping it would make the walk
    /// exactly as good as not having one. A directory without search permission in
    /// the chain makes everything below it un-stat-able.
    #[test]
    fn an_ancestor_that_cannot_be_stated_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        // Readable but not searchable: stat of anything below fails with EACCES,
        // which is not "does not exist" and must not be treated as it.
        chmod(&locked, 0o600);

        let err = check(&dir, &locked.join("sub/decisions.jsonl"), None).unwrap_err();
        // Restore search permission first so the tempdir can clean up after itself.
        chmod(&locked, 0o700);
        let text = err.to_string();
        assert!(
            matches!(err, IsolationError::Io { .. }),
            "an uninspectable ancestor must fail closed, got {text}"
        );
        assert!(
            text.contains("locked/sub"),
            "the uninspectable ancestor must be named: {text}"
        );
    }

    #[test]
    fn an_owner_only_directory_outside_the_cwd_passes_without_warnings() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());

        let warnings = check(
            &dir,
            &root.path().join("state/decisions.jsonl"),
            Some(elsewhere.path()),
        )
        .unwrap();
        assert!(warnings.is_empty(), "{warnings:#?}");
    }

    /// The dev shortcut. It must keep working — but an operator has to be able to
    /// tell it apart from a safe deployment, and the warning has to say what the
    /// real control is, since file modes are not it.
    #[test]
    fn a_policy_directory_inside_the_cwd_warns_and_names_the_risk() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());

        let warnings = check(
            &dir,
            &elsewhere.path().join("decisions.jsonl"),
            Some(root.path()),
        )
        .unwrap();
        let text = warnings.join("\n");
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(
            text.contains(&dir.display().to_string()),
            "the warning must name the directory: {text}"
        );
        assert!(
            text.contains("fs_write"),
            "the warning must name the profile keys that grant the access: {text}"
        );
        assert!(
            text.contains("same user"),
            "the warning must say why file modes do not help: {text}"
        );
        assert!(
            text.contains("cannot read"),
            "the warning must admit it is a proxy for the real rule: {text}"
        );
    }

    /// A relative `policy_dir` — what the repo's dev config uses — is inside the
    /// working directory by definition, and must warn like any other.
    #[test]
    fn a_relative_policy_directory_is_measured_against_the_cwd() {
        let root = tempfile::tempdir().unwrap();
        let _dir = policy_dir(root.path());

        let warnings = check(
            Path::new("./policies"),
            Path::new("./decisions.jsonl"),
            Some(root.path()),
        )
        .unwrap();
        assert_eq!(
            warnings.len(),
            2,
            "both the policy dir and the audit log are inside the cwd: {warnings:#?}"
        );
    }

    /// The audit log is the record of what was decided, so an agent that can write
    /// the tree it sits in can rewrite that record.
    #[test]
    fn an_audit_log_inside_the_cwd_warns_about_the_trail() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let dir = policy_dir(elsewhere.path());

        let warnings = check(
            &dir,
            &root.path().join("decisions.jsonl"),
            Some(root.path()),
        )
        .unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        let text = warnings.join("\n");
        assert!(text.contains("decisions.jsonl"), "{text}");
        assert!(
            text.contains("audit"),
            "the warning must name what is at stake: {text}"
        );
    }

    /// A path that does not exist yet — the audit log before its first record —
    /// still has to be comparable with the working directory. On macOS the answer
    /// is wrong unless the existing part is symlink-resolved: `/var` is a symlink
    /// to `/private/var`, which is exactly where `tempfile` puts things.
    #[test]
    fn a_not_yet_created_audit_log_is_still_located() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        let unresolved = PathBuf::from("/var").join(
            root.path()
                .strip_prefix("/private/var")
                .unwrap_or(Path::new(".")),
        );
        let cwd = if unresolved.exists() {
            unresolved
        } else {
            root.path().to_path_buf()
        };

        let warnings = check(&dir, &cwd.join("state/decisions.jsonl"), Some(&cwd)).unwrap();
        assert_eq!(
            warnings.len(),
            2,
            "an audit log that does not exist yet is still inside the cwd: {warnings:#?}"
        );
    }
}
