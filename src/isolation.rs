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
//! Modes are not the whole check, because an owner may change them at will:
//! every checked component — the policy directory, each loadable policy file,
//! every existing ancestor of both state paths, and the audit log file once it
//! exists — must also be **owned by the daemon's effective uid or by root**
//! (D6). A component another local user owns passes every mode test while its
//! owner keeps the power to chmod, rename or rewrite it; the sticky bit stops
//! renames of entries you do not own, but it does not stop an attacker
//! *pre-creating* a then-missing component (the policy directory under a
//! `/tmp`-style ancestor, the audit log before its first record) and owning it.
//! Root is trusted deliberately: a root-installed policy pack this daemon
//! cannot write is *stronger* than a user-owned one, system ancestors (`/`,
//! `/Users`) are root-owned everywhere, and owner-or-root is the rule OpenSSH's
//! `StrictModes` applies to `~/.ssh`. Ownership closes pre-creation — it cannot
//! see in-place history: a file this user owns whose *content* changed while
//! its mode was loose is adopted once the mode is repaired, which is why the
//! writability remedy tells the operator to review before tightening (content
//! provenance beyond that is epic #1's policy-signing child). And like the mode
//! checks, ownership defends against other local users only — the sandboxed
//! agent runs as the same uid and owns these paths already.
//!
//! One more rule makes the two above mean what they say: `serve` **resolves the
//! configured paths once**, at startup and before any check (D7 — `policy_dir`
//! through `canonicalize`, the audit log through [`resolve_existing_prefix`]),
//! and constructs the engine, the watcher and the audit log with the resolved
//! paths. The checked chain and the used chain are therefore the same object: a
//! symlink on the *configured* path cannot be repointed after startup to
//! redirect a reload to a tree these checks never walked (that gap was live
//! before D7 — the walk inspected the canonical chain while the loader
//! traversed the configured lexical one), and a symlink already pointing into
//! another user's tree at startup is caught by the ownership rule on the
//! resolved components. The residual, named rather than hidden: an attacker who
//! can write a lexical component's holding directory can still, *before
//! startup*, point the link at a stale tree this daemon's user genuinely owns —
//! every resolved-chain check passes, because the tree really is ours. That
//! takes an unusual configured path (the shipped home-anchored defaults have no
//! foreign-writable lexical components) and a useful stale tree to exist; the
//! complete answer is the profile-derived check and policy signing under
//! epic #1.
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
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    #[error(
        "{what} {path} is {who}-writable (mode {mode}) — another local user could add or \
         rewrite a policy and decide this daemon's approvals, so it refuses to serve. Fix with \
         `chmod go-w {path}` (a user-private group counts: this process cannot tell one from a \
         shared group) — but review the contents first: tightening the mode does not undo \
         content added or modified while the path was writable by others. This says nothing \
         about a sandboxed agent, which runs as the same user as this daemon and is bounded \
         only by its nono profile's write grants"
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
        "{what} {path} is owned by uid {owner}, which is neither this daemon's user (uid \
         {euid}) nor root — an owner can loosen, rename or rewrite a path at will, so a mode \
         that looks tight proves nothing about who controls it (a component another local \
         user pre-created under a /tmp-style sticky ancestor passes every mode test this \
         way: sticky stops renames of entries you do not own, not creation), and the daemon \
         refuses to serve. Recreate the path under a directory this user owns, or have root \
         take ownership of it. This says nothing about a sandboxed agent, which runs as the \
         same user as this daemon and is bounded only by its nono profile's write grants"
    )]
    ForeignOwner {
        what: &'static str,
        path: PathBuf,
        owner: u32,
        euid: u32,
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
    let euid = daemon_euid();
    let base = cwd.map(|c| absolutize(c, None));
    let policy_dir = absolutize(policy_dir, base.as_deref());
    let audit_log = absolutize(audit_log, base.as_deref());

    refuse_untrusted_policy_dir_as(&policy_dir, euid)?;
    refuse_on_untrusted_ancestors("audit log", "ancestor of the audit log", &audit_log, euid)?;
    refuse_a_foreign_owned_audit_log(&audit_log, euid)?;

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
/// file the loader would load, and the existing ancestor chain — each judged on
/// its mode *and* its owner (owner-or-root, D6).
///
/// One implementation, two callers (D5): [`check`] at startup, and the watcher
/// before every reload — so the startup path and the reload path cannot drift
/// apart. No cwd warnings here: those are advisory posture messages, and repeating
/// them on every debounce would train operators to filter ERROR-adjacent output.
/// Like everything in this module, an `Err` defends against other local users; it
/// says nothing about the sandboxed agent, which runs as the same user as this
/// daemon.
pub(crate) fn refuse_untrusted_policy_dir(policy_dir: &Path) -> Result<(), IsolationError> {
    refuse_untrusted_policy_dir_as(policy_dir, daemon_euid())
}

/// [`refuse_untrusted_policy_dir`] with the effective uid passed in: the seam
/// that lets the foreign-owner rows of the truth table run against real
/// fixtures, since `chown` needs privileges the test suite does not have —
/// pretending to be a different euid makes a self-owned fixture foreign.
fn refuse_untrusted_policy_dir_as(policy_dir: &Path, euid: u32) -> Result<(), IsolationError> {
    // Absolutize so the ancestor walk runs over the real, symlink-resolved chain.
    // Idempotent for the already-absolutized path `check` passes; the watcher
    // hands over the configured (possibly repo-relative) path as-is.
    let policy_dir = absolutize(policy_dir, None);
    refuse_if_untrusted("policy directory", &policy_dir, euid)?;
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
        if path.extension().is_none_or(|e| e != "cedar") {
            continue;
        }
        if !crate::cedar::engine::is_loadable_policy_file(&path) {
            continue;
        }
        // Follows symlinks on purpose: the loader reads through them, so the mode
        // (and owner) that decides who can change a policy is the target's.
        refuse_if_untrusted("policy file", &path, euid)?;
    }
    refuse_on_untrusted_ancestors(
        "policy directory",
        "ancestor of the policy directory",
        &policy_dir,
        euid,
    )
}

/// The daemon's effective uid: besides root, the one identity whose ownership of
/// a state-path component is not a refusal.
fn daemon_euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail —
    // it only reads this process's credentials from the kernel.
    unsafe { libc::geteuid() }
}

/// What the trust decision needs to know about one filesystem component, split
/// from *reading* it so the refusal truth table can be driven with injected
/// values: the suite cannot `chown`, so the foreign- and root-owned rows are
/// unbuildable as real fixtures (same seam style as `cwd` being passed into
/// [`check`] rather than read from the process).
#[derive(Debug, Clone, Copy)]
struct ComponentFacts {
    owner_uid: u32,
    /// Permission bits plus setuid/setgid/sticky: `st_mode & 0o7777`.
    mode: u32,
    is_dir: bool,
}

impl ComponentFacts {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            owner_uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            is_dir: metadata.is_dir(),
        }
    }
}

fn refuse_if_untrusted(what: &'static str, path: &Path, euid: u32) -> Result<(), IsolationError> {
    let metadata = std::fs::metadata(path).map_err(|source| IsolationError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    judge_component(what, path, ComponentFacts::of(&metadata), euid)
}

/// The refusal truth table for a directly-checked component — the policy
/// directory or a loadable policy file. Ownership is judged first: a foreign
/// owner can undo at will any mode this check might approve of, so a tight mode
/// on a foreign-owned path proves nothing.
fn judge_component(
    what: &'static str,
    path: &Path,
    facts: ComponentFacts,
    euid: u32,
) -> Result<(), IsolationError> {
    if let Some(owner) = foreign_owner(facts.owner_uid, euid) {
        return Err(IsolationError::ForeignOwner {
            what,
            path: path.to_path_buf(),
            owner,
            euid,
        });
    }
    if let Some(who) = loose_writers(facts.mode) {
        return Err(IsolationError::Writable {
            what,
            path: path.to_path_buf(),
            mode: format!("{:04o}", facts.mode),
            who: who.to_string(),
        });
    }
    Ok(())
}

/// The owning uid when it is neither `euid` nor root — i.e. when someone else
/// holds the power to chmod, rename or rewrite the component regardless of its
/// current mode. Root is trusted deliberately (D6): a root-installed, root-owned
/// policy pack the daemon cannot write is *stronger* than a user-owned one,
/// system ancestors (`/`, `/Users`, `/tmp`) are root-owned everywhere, and
/// owner-or-root is the same rule OpenSSH's `StrictModes` applies to `~/.ssh`.
fn foreign_owner(owner_uid: u32, euid: u32) -> Option<u32> {
    (owner_uid != euid && owner_uid != 0).then_some(owner_uid)
}

/// The audit log file itself, once it exists, is a checked component too (D6).
/// Its *mode* stays a tighten-on-open, not a refusal (`src/audit.rs`: a trail
/// the daemon cannot keep private is still better recorded than not), but a
/// foreign *owner* is different — the owner can rewrite or truncate the record
/// no matter what mode the open tightens it to, and pre-creating the log before
/// its first record is exactly the attack ownership closes. Startup-only, like
/// every audit-log check here: mid-session detachment is `src/audit.rs`'s
/// reattach concern, and the reload gate is about the policy set.
fn refuse_a_foreign_owned_audit_log(audit_log: &Path, euid: u32) -> Result<(), IsolationError> {
    match std::fs::metadata(audit_log) {
        Ok(metadata) => match foreign_owner(metadata.uid(), euid) {
            Some(owner) => Err(IsolationError::ForeignOwner {
                what: "audit log",
                path: audit_log.to_path_buf(),
                owner,
                euid,
            }),
            None => Ok(()),
        },
        // Not created yet: the open creates it 0600 under this uid, and the
        // ancestor rules above govern who could have created it first. A
        // non-directory ancestor (`/dev/null/decisions.jsonl`) is the open's
        // honest ENOTDIR, not this check's business — same posture as the walk.
        Err(source)
            if matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(())
        }
        Err(source) => Err(IsolationError::Io {
            path: audit_log.to_path_buf(),
            source,
        }),
    }
}

/// Walk every existing ancestor of `path` — its parent up to the root — and refuse
/// on one that is group- or world-writable without the sticky bit, or owned by
/// neither the daemon's user nor root.
///
/// `path` is already absolutized, so the chain being walked is the real one, not a
/// lexical guess through symlinks. An ancestor that does not exist yet (the audit
/// log's directory before the first record) cannot have its entries renamed by
/// anyone and is skipped; an ancestor that exists but cannot be inspected is a
/// refusal — an unknown mode has to count as a loose one, or the walk is exactly as
/// good as not having one.
fn refuse_on_untrusted_ancestors(
    what: &'static str,
    ancestor_what: &'static str,
    path: &Path,
    euid: u32,
) -> Result<(), IsolationError> {
    let mut current = path.parent();
    while let Some(ancestor) = current {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match std::fs::metadata(ancestor) {
            Ok(metadata) => judge_ancestor(
                what,
                ancestor_what,
                path,
                ancestor,
                ComponentFacts::of(&metadata),
                euid,
            )?,
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

/// The refusal truth table for one existing *ancestor* of a state path.
///
/// Ownership before mode, for the same reason as [`judge_component`] — and with
/// one difference from the mode rule: the sticky bit exempts an ancestor from
/// the *writability* refusal (it blocks the rename attack), but it exempts
/// nothing from the *ownership* one, because a directory's owner may rename any
/// entry in it and may drop the sticky bit at will.
fn judge_ancestor(
    what: &'static str,
    ancestor_what: &'static str,
    path: &Path,
    ancestor: &Path,
    facts: ComponentFacts,
    euid: u32,
) -> Result<(), IsolationError> {
    // Only a directory can host the rename. Mode bits on a file or device
    // ancestor (`/dev/null/decisions.jsonl` is the config typo that hits this)
    // grant no power over directory entries, and nothing below one can ever
    // exist — the audit log's own open fails with an honest "not a directory"
    // instead of a rename warning that cannot apply. Ownership is moot for the
    // same reason: there is nothing below the non-directory to substitute.
    if !facts.is_dir {
        return Ok(());
    }
    if let Some(owner) = foreign_owner(facts.owner_uid, euid) {
        return Err(IsolationError::ForeignOwner {
            what: ancestor_what,
            path: ancestor.to_path_buf(),
            owner,
            euid,
        });
    }
    if let Some(who) = loose_ancestor_writers(facts.mode) {
        return Err(IsolationError::WritableAncestor {
            what,
            path: path.to_path_buf(),
            ancestor: ancestor.to_path_buf(),
            mode: format!("{:04o}", facts.mode),
            who: who.to_string(),
        });
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

/// Absolute, symlink-resolved form of a configured state path whose full chain
/// may not exist yet — the audit log before its first record: as much of the
/// path as exists is canonicalized and the rest is appended lexically.
///
/// `serve` resolves both configured paths exactly once, at startup and before
/// the checks (D7; `policy_dir` must exist, so it goes through plain
/// `canonicalize`) — so the chain the checks walk and the chain the loader, the
/// watcher and the audit log use are the same object, and a symlink on the
/// *configured* path repointed after startup changes nothing the daemon will
/// ever read. See the module docs for the one residual this leaves.
pub fn resolve_existing_prefix(path: &Path) -> PathBuf {
    absolutize(path, None)
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

    /// Tightening a mode is not a time machine: content added or modified while
    /// the path was loose survives `chmod go-w`, so the remedy must send the
    /// operator to review before they trust the tightened directory. (The
    /// planted-*file* half is closed by ownership — a file someone else created
    /// stays theirs — but content changed in place in a file we own is history
    /// no re-check can see; design D6's named limit.)
    #[test]
    fn the_writability_remedy_warns_that_chmod_does_not_undo_content_changed_while_loose() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        chmod(&dir, 0o770);

        let err = check(&dir, &root.path().join("decisions.jsonl"), None).unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, IsolationError::Writable { .. }), "{text}");
        assert!(
            text.contains("review"),
            "the remedy must send the operator to review the contents: {text}"
        );
        assert!(
            text.contains("does not undo"),
            "the remedy must say what chmod cannot fix: {text}"
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

    /// The uids the injected-facts rows run under. Arbitrary values: only the
    /// same/other/root relationships matter to the truth table.
    const EUID: u32 = 500;
    const FOREIGN: u32 = 501;

    /// D6's core row: a component owned by someone else passes every mode test
    /// while its owner can chmod, rename or rewrite it at will, so a tight mode
    /// proves nothing and the refusal must fire on ownership alone.
    #[test]
    fn a_foreign_owned_component_refuses_no_matter_how_tight_the_mode() {
        let facts = ComponentFacts {
            owner_uid: FOREIGN,
            mode: 0o700,
            is_dir: true,
        };
        let err =
            judge_component("policy directory", Path::new("/x/policies"), facts, EUID).unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, IsolationError::ForeignOwner { .. }),
            "want an ownership refusal, got {text}"
        );
        assert!(
            text.contains("/x/policies"),
            "the path must be named: {text}"
        );
        assert!(
            text.contains("501"),
            "the owning uid must be named: {text}"
        );
        assert!(
            text.contains("root"),
            "the rule is owner-or-root and the message must say so: {text}"
        );
        assert!(
            text.contains("mode"),
            "the message must explain why ownership matters when the mode looks tight: {text}"
        );
        assert!(
            text.contains("same user"),
            "scope honesty: this defends against other local users, not the agent: {text}"
        );

        // Same row for a policy file: the loader reads through it either way.
        let file_facts = ComponentFacts {
            owner_uid: FOREIGN,
            mode: 0o600,
            is_dir: false,
        };
        let err = judge_component(
            "policy file",
            Path::new("/x/policies/p.cedar"),
            file_facts,
            EUID,
        )
        .unwrap_err();
        assert!(matches!(err, IsolationError::ForeignOwner { .. }), "{err}");
    }

    /// The root-owned PASS rows — the reason "or root" is in the rule at all:
    /// `/`, `/Users` and `/tmp` (1777, sticky) are root-owned on every macOS and
    /// Linux system, and a root-installed pack the daemon cannot write is
    /// *stronger* than a user-owned one. The suite cannot create root-owned
    /// fixtures, so these rows run on injected facts; the real-chain PASS side
    /// is every other test in this module, whose fixture ancestors are all
    /// root- or self-owned.
    #[test]
    fn root_owned_components_and_ancestors_pass() {
        judge_component(
            "policy directory",
            Path::new("/etc/pdp/policies"),
            ComponentFacts {
                owner_uid: 0,
                mode: 0o755,
                is_dir: true,
            },
            EUID,
        )
        .unwrap_or_else(|e| panic!("a root-owned policy directory must pass: {e}"));
        judge_ancestor(
            "policy directory",
            "ancestor of the policy directory",
            Path::new("/etc/pdp/policies"),
            Path::new("/"),
            ComponentFacts {
                owner_uid: 0,
                mode: 0o755,
                is_dir: true,
            },
            EUID,
        )
        .unwrap_or_else(|e| panic!("a root-owned ancestor must pass: {e}"));
        // `/tmp` itself: root-owned, world-writable, sticky.
        judge_ancestor(
            "audit log",
            "ancestor of the audit log",
            Path::new("/tmp/pdp/decisions.jsonl"),
            Path::new("/tmp"),
            ComponentFacts {
                owner_uid: 0,
                mode: 0o1777,
                is_dir: true,
            },
            EUID,
        )
        .unwrap_or_else(|e| panic!("a root-owned sticky 1777 ancestor must pass: {e}"));
    }

    /// The sticky bit exempts an ancestor from the *writability* refusal only:
    /// the directory's owner may rename any entry in it, and may drop the sticky
    /// bit at will, so a foreign-owned sticky ancestor is still a refusal.
    #[test]
    fn a_foreign_owned_sticky_ancestor_still_refuses() {
        let err = judge_ancestor(
            "policy directory",
            "ancestor of the policy directory",
            Path::new("/x/policies"),
            Path::new("/x"),
            ComponentFacts {
                owner_uid: FOREIGN,
                mode: 0o1777,
                is_dir: true,
            },
            EUID,
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, IsolationError::ForeignOwner { .. }),
            "sticky must not exempt ownership: {text}"
        );
        assert!(
            text.contains("ancestor of the policy directory"),
            "the message must say which chain this sits on: {text}"
        );
        assert!(text.contains("/x"), "the ancestor must be named: {text}");
    }

    /// Non-directory ancestors stay out of the walk's business whoever owns
    /// them: nothing below one can ever exist, so the state path's own open
    /// fails with the honest ENOTDIR (same rationale as the mode-side skip).
    #[test]
    fn a_non_directory_ancestor_is_skipped_whoever_owns_it() {
        judge_ancestor(
            "audit log",
            "ancestor of the audit log",
            Path::new("/dev/null/decisions.jsonl"),
            Path::new("/dev/null"),
            ComponentFacts {
                owner_uid: FOREIGN,
                mode: 0o666,
                is_dir: false,
            },
            EUID,
        )
        .unwrap_or_else(|e| panic!("a non-directory ancestor is the open's error, not ours: {e}"));
    }

    /// Passing the ownership test must not shadow the mode test: a self-owned
    /// but group-writable component is still the original refusal.
    #[test]
    fn a_self_owned_component_is_still_judged_by_its_mode() {
        let err = judge_component(
            "policy directory",
            Path::new("/x/policies"),
            ComponentFacts {
                owner_uid: EUID,
                mode: 0o770,
                is_dir: true,
            },
            EUID,
        )
        .unwrap_err();
        assert!(matches!(err, IsolationError::Writable { .. }), "{err}");
    }

    /// D6 through the real metadata path: the fixture is owned by whoever runs
    /// the suite, so pretending to be a *different* euid makes it foreign-owned
    /// without the chown the suite cannot do. The public wrapper supplies the
    /// real euid; everything below the seam is the same code.
    #[test]
    fn a_policy_directory_owned_by_another_uid_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let dir = policy_dir(root.path());
        let owner = std::fs::metadata(&dir).unwrap().uid();

        let err = refuse_untrusted_policy_dir_as(&dir, owner + 1).unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, IsolationError::ForeignOwner { .. }),
            "want an ownership refusal, got {text}"
        );
        assert!(
            text.contains(&dir.display().to_string()),
            "the path must be named: {text}"
        );
        assert!(
            text.contains(&owner.to_string()),
            "the owning uid must be named: {text}"
        );
    }

    /// The ancestor half of the same real-metadata proof, driven through the
    /// walk itself so the refusal provably lands on the ancestor.
    #[test]
    fn an_ancestor_owned_by_another_uid_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let holder = root.path().join("holder");
        std::fs::create_dir(&holder).unwrap();
        let dir = policy_dir(&holder);
        let owner = std::fs::metadata(&holder).unwrap().uid();

        let err = refuse_on_untrusted_ancestors(
            "policy directory",
            "ancestor of the policy directory",
            &absolutize(&dir, None),
            owner + 1,
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, IsolationError::ForeignOwner { .. }),
            "want an ownership refusal, got {text}"
        );
        assert!(
            text.contains(&holder.display().to_string()),
            "the ancestor must be named: {text}"
        );
    }

    /// The audit log file, once it exists, is a checked component too: its mode
    /// stays tighten-on-open, but a foreign owner can rewrite the record no
    /// matter what the open tightens the mode to — the pre-created-file half of
    /// the attack.
    #[test]
    fn an_audit_log_owned_by_another_uid_refuses_to_serve() {
        let root = tempfile::tempdir().unwrap();
        let log = root.path().join("decisions.jsonl");
        std::fs::write(&log, "").unwrap();
        let owner = std::fs::metadata(&log).unwrap().uid();

        let err = refuse_a_foreign_owned_audit_log(&log, owner + 1).unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, IsolationError::ForeignOwner { .. }),
            "want an ownership refusal, got {text}"
        );
        assert!(text.contains("audit log"), "{text}");
        assert!(
            text.contains(&log.display().to_string()),
            "the path must be named: {text}"
        );
    }

    /// Before the first record there is nothing to own — the open creates the
    /// log 0600 under this uid, and the ancestor rules govern who could have
    /// created it first. And a non-directory ancestor stays the open's honest
    /// ENOTDIR, not an ownership refusal.
    #[test]
    fn a_missing_audit_log_is_not_an_ownership_refusal() {
        let root = tempfile::tempdir().unwrap();
        refuse_a_foreign_owned_audit_log(&root.path().join("decisions.jsonl"), EUID)
            .unwrap_or_else(|e| panic!("a not-yet-created audit log must pass: {e}"));

        let blocker = root.path().join("blocker.txt");
        std::fs::write(&blocker, "not a directory").unwrap();
        refuse_a_foreign_owned_audit_log(&blocker.join("decisions.jsonl"), EUID)
            .unwrap_or_else(|e| panic!("ENOTDIR is the open's error, not this check's: {e}"));
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
