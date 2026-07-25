//! Policy set loading, strict validation, and the hot-swappable current set.

use arc_swap::ArcSwap;
use cedar_policy::{Effect, PolicyId, PolicySet, Schema, ValidationMode, Validator};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Debug, thiserror::Error)]
pub enum PolicyLoadError {
    #[error("reading policy dir {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("reading policy file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("duplicate policy id from {path}: {message}")]
    Duplicate { path: PathBuf, message: String },
    #[error("policy validation failed against the nono schema: {}", .errors.join("; "))]
    Validation { errors: Vec<String> },
    #[error(
        "no policies found in {path} (checked every *.cedar file) — refusing to serve a deny-everything policy set"
    )]
    Empty { path: PathBuf },
}

/// Why a `*.cedar` entry is deliberately skipped rather than failed on: editor lock
/// files and backups (`.#10-git.cedar`, `#10-git.cedar#`), and anything that is not
/// a regular file (a directory named `archive.cedar`, a dangling symlink). Failing
/// on these would block startup — and every hot-reload — for as long as a policy
/// file is open in an editor.
///
/// `None` means loadable. The reason is a sentence for the operator, because a
/// skipped file is a policy they wrote that decides nothing: `load_dir` logs one
/// WARN per skip naming the path and this reason (a silently ignored
/// `.baseline.cedar` is a hole with no trace).
pub(crate) fn policy_file_skip_reason(path: &Path) -> Option<&'static str> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Some("its name is not valid UTF-8");
    };
    if name.starts_with('.') || name.starts_with('#') {
        return Some(
            "its name starts with '.' or '#', the shape editors give lock files and \
             backups — rename it if it is a real policy",
        );
    }
    if !path.is_file() {
        return Some(
            "it is not a regular file: a directory, a socket, or a symlink whose \
             target is missing",
        );
    }
    None
}

/// Whether `load_dir` will load this path. Shared with [`crate::isolation`] so the
/// startup mode check inspects exactly the files that get a say in decisions.
pub(crate) fn is_loadable_policy_file(path: &Path) -> bool {
    policy_file_skip_reason(path).is_none()
}

/// Operator lints for the two argument-matching hazards that survive the schema.
///
/// The anchoring hazard is gone structurally: there is no whole-`argv` attribute,
/// so a policy that reaches for one is refused by strict validation rather than
/// warned about. What is left needs advice, not a wall:
///
/// 1. **A `permit` whose `argv_tail` test is not a positional pin.** `argv_tail` is
///    a joined string, so an unanchored glob such as `argv_tail like "*--force*"`
///    also matches when the text sits *inside* a single argument
///    (`-m "do not --force this"`), and it cannot tell `["push --force"]` from
///    `["push", "--force"]`. Over-matching is fail-safe in a `forbid` and unsound in
///    a `permit`. A pattern anchored at the start *and ended at the separating space*
///    (`like "status *"`), or an equality test (`== "status"`), is a different thing:
///    it pins the FIRST token of `args[1..]`, which is the git-style subcommand, and
///    that is the one thing set membership cannot express. Those are the sound shape
///    for a `permit` and are not flagged. A pin that stops mid-token (`like "diff*"`,
///    which also matches `difftool --extcmd=<cmd>`) is flagged like an unanchored
///    glob: it approves more than it names.
/// 2. **An `args` membership test against a value containing `/`.** `args` stays
///    faithful to the payload, so `args[0]` is the per-run shim path
///    (`…/nono-tool-sandbox-<pid>-<nanos>-<hex>/shims/<command>`): a literal that
///    is meant to pin the program can never match it — fail-open in a `forbid`,
///    which is why this one is flagged for both effects. It over-reports by
///    design: `args.contains("/etc/passwd")` about a path *argument* is sound and
///    still gets a line, because the two are indistinguishable from here and the
///    fail-open reading is the dangerous one.
///
/// Advisory, not fatal: the operator may have a narrow case, and refusing to start
/// on a heuristic would be a worse failure mode than a warning.
pub fn lint_arg_matching(set: &PolicySet) -> Vec<String> {
    let mut lints = Vec::new();
    for policy in set.policies() {
        // Inspect the JSON form, not the source text: a comment that merely
        // mentions argv_tail is not a read of it.
        let json = match policy.to_json() {
            Ok(json) => json,
            Err(e) => {
                tracing::debug!(policy = %policy.id(), error = %e, "could not lint policy");
                continue;
            }
        };

        if policy.effect() == Effect::Permit && unpinned_argv_tail_reads(&json) > 0 {
            lints.push(format!(
                "policy {} is a permit whose resource.argv_tail test does not pin a \
                 whole token; a glob that starts with a wildcard over-matches text \
                 inside a single argument, and one that stops mid-token (like \
                 \"diff*\") also matches a longer subcommand (difftool), so either \
                 belongs in forbid only — anchor the pattern and end it at the \
                 separating space (like \"status *\"), or compare it exactly \
                 (== \"status\"), and use resource.args.contains(..) for flags",
                policy.id()
            ));
        }

        for literal in args_membership_path_literals(&json) {
            lints.push(format!(
                "policy {} tests resource.args membership against {literal:?}, \
                 which contains a path separator; args[0] is an absolute per-run \
                 shim path that no literal can match, so if this is meant to pin \
                 the program it never matches — match resource.command instead \
                 (harmless if it really is a path argument)",
                policy.id()
            ));
        }
    }
    lints
}

/// How many reads of `resource.argv_tail` in this policy are **not** positional
/// pins. Walks the policy's JSON (EST) form rather than its source text, so a
/// comment mentioning the attribute is not a read of it.
///
/// A read is a pin when it is the left side of a `like` whose pattern starts with a
/// literal and ends that literal at the separating space (`like "status *"` — the join
/// can only satisfy it by having that whole token first), or either side of an `==` (an
/// exact whole-string test). Every other read — a pattern starting with `*`, one that
/// stops mid-token (`"diff*"` also matches `difftool`), a negation, an argv_tail buried
/// in some other operator — can be satisfied by text the author did not name, which is
/// what makes it unsound in a `permit`.
fn unpinned_argv_tail_reads(json: &serde_json::Value) -> usize {
    fn is_argv_tail(node: &serde_json::Value) -> bool {
        node.get(".")
            .and_then(|access| access.get("attr"))
            .and_then(serde_json::Value::as_str)
            == Some("argv_tail")
    }

    /// A `like` pattern is a list of `{"Literal": "c"}` and `"Wildcard"` elements. It
    /// pins a token when it starts with a literal AND that literal run ends where the
    /// argument ends — either the pattern has no wildcard at all (an exact test) or the
    /// first wildcard is preceded by the space that separates joined arguments.
    ///
    /// `like "diff*"` is anchored but stops mid-token, so it also matches `difftool
    /// --extcmd=<cmd>`, which executes `<cmd>`: pinning half a token is the same
    /// over-match the lint exists for.
    fn pins_a_token(pattern: &serde_json::Value) -> bool {
        let Some(elements) = pattern.as_array() else {
            return false;
        };
        let is_wildcard = |e: &serde_json::Value| e.as_str() == Some("Wildcard");
        match elements.iter().position(is_wildcard) {
            // A pure literal pattern is an exact test.
            None => true,
            // A leading wildcard is a search, not a pin.
            Some(0) => false,
            Some(first) => {
                elements[first - 1]
                    .get("Literal")
                    .and_then(serde_json::Value::as_str)
                    == Some(" ")
            }
        }
    }

    fn walk(node: &serde_json::Value, out: &mut usize) {
        match node {
            serde_json::Value::Object(map) => {
                if let Some(like) = map.get("like") {
                    if like.get("left").is_some_and(is_argv_tail) {
                        if !like.get("pattern").is_some_and(pins_a_token) {
                            *out += 1;
                        }
                        // The read is accounted for; the pattern holds no expressions.
                        return;
                    }
                }
                if let Some(equality) = map.get("==") {
                    let sides = [equality.get("left"), equality.get("right")];
                    if sides.iter().flatten().copied().any(is_argv_tail) {
                        // Sound: descend only into whatever the other side is.
                        for side in sides.into_iter().flatten() {
                            if !is_argv_tail(side) {
                                walk(side, out);
                            }
                        }
                        return;
                    }
                }
                if is_argv_tail(node) {
                    *out += 1;
                    return;
                }
                for value in map.values() {
                    walk(value, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, out);
                }
            }
            _ => {}
        }
    }

    let mut out = 0;
    walk(json, &mut out);
    out
}

/// Every string literal a policy compares against `resource.args` membership that
/// contains a `/`. Walks the policy's JSON (EST) form, so it sees `contains`,
/// `containsAny` and `containsAll` wherever they are nested.
fn args_membership_path_literals(json: &serde_json::Value) -> Vec<String> {
    fn is_args_attr(node: &serde_json::Value) -> bool {
        node.get(".")
            .and_then(|access| access.get("attr"))
            .and_then(serde_json::Value::as_str)
            == Some("args")
    }

    fn string_literals(node: &serde_json::Value, out: &mut Vec<String>) {
        if let Some(value) = node.get("Value").and_then(serde_json::Value::as_str) {
            out.push(value.to_string());
        }
        if let Some(items) = node.get("Set").and_then(serde_json::Value::as_array) {
            for item in items {
                string_literals(item, out);
            }
        }
    }

    fn walk(node: &serde_json::Value, out: &mut Vec<String>) {
        match node {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    if matches!(key.as_str(), "contains" | "containsAny" | "containsAll") {
                        let left = value.get("left");
                        let right = value.get("right");
                        if let (Some(left), Some(right)) = (left, right) {
                            if is_args_attr(left) {
                                let mut literals = Vec::new();
                                string_literals(right, &mut literals);
                                out.extend(literals.into_iter().filter(|l| l.contains('/')));
                            }
                        }
                    }
                    walk(value, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, out);
                }
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    walk(json, &mut out);
    out
}

#[derive(Debug)]
pub struct LoadedPolicies {
    pub set: PolicySet,
    pub generation: u64,
    pub loaded_at: SystemTime,
    pub files: Vec<PathBuf>,
}

/// Read every `*.cedar` file in `dir`, assign provenance-carrying policy ids,
/// and strict-validate the whole set against `schema`.
///
/// Policy ids are `<file stem>:<@id annotation or ordinal>`, so a decision's
/// reason string points at the file that produced it.
pub fn load_dir(
    dir: &Path,
    schema: &Schema,
    generation: u64,
) -> Result<LoadedPolicies, PolicyLoadError> {
    let listing = std::fs::read_dir(dir).map_err(|source| PolicyLoadError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    load_entries(dir, listing.map(|e| e.map(|e| e.path())), schema, generation)
}

/// The whole load, from a directory listing already in hand. Split from
/// [`load_dir`] so a unit test can inject an `Err` entry — the enumeration
/// failure `read_dir` can yield on a real filesystem but no hermetic test can
/// produce (same seam style as `audit::ByteSink`); the production call site
/// above stays one line.
fn load_entries(
    dir: &Path,
    listing: impl IntoIterator<Item = std::io::Result<PathBuf>>,
    schema: &Schema,
    generation: u64,
) -> Result<LoadedPolicies, PolicyLoadError> {
    // A skip is announced, never silent — and a skip is only ever a *classified*
    // file. An entry the listing itself fails to yield is refused outright: the
    // loader cannot classify what it could not read, so it cannot know the entry
    // was not a policy, and an unreadable entry in a policy directory is the
    // shape of a tampering symptom. The failure belongs to enumerating `dir`,
    // not to any named file, hence `Io` rather than `ReadFile`.
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in listing {
        let path = entry.map_err(|source| PolicyLoadError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        if !path.extension().is_some_and(|e| e == "cedar") {
            continue;
        }
        // The file is a policy the operator wrote and this daemon will not
        // enforce, and the log is the only place they can find that out.
        match policy_file_skip_reason(&path) {
            Some(reason) => tracing::warn!(
                path = %path.display(),
                reason,
                "skipping a *.cedar file: it is not loaded and decides nothing"
            ),
            None => entries.push(path),
        }
    }
    entries.sort();

    let mut set = PolicySet::new();
    for path in &entries {
        let text = std::fs::read_to_string(path).map_err(|source| PolicyLoadError::ReadFile {
            path: path.clone(),
            source,
        })?;
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "policy".to_string());

        let parsed = PolicySet::from_str(&text).map_err(|e| PolicyLoadError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;

        for (ordinal, policy) in parsed.policies().enumerate() {
            let id = match policy.annotation("id") {
                Some(a) => PolicyId::new(format!("{stem}:{a}")),
                None => PolicyId::new(format!("{stem}:{ordinal}")),
            };
            set.add(policy.new_id(id))
                .map_err(|e| PolicyLoadError::Duplicate {
                    path: path.clone(),
                    message: e.to_string(),
                })?;
        }
    }

    checked(set, schema, dir, generation, entries)
}

/// The guards every set passes before it can decide anything, wherever the set came
/// from: non-empty, strict-validated against `schema`, lints logged. `source` names
/// the directory the set belongs to, for the error message only.
///
/// Factored out so no constructor can acquire a policy set without them — the
/// zero-policy state in particular is the one an `Engine` must never hold (see
/// [`Engine::from_policy_set`]).
fn checked(
    set: PolicySet,
    schema: &Schema,
    source: &Path,
    generation: u64,
    files: Vec<PathBuf>,
) -> Result<LoadedPolicies, PolicyLoadError> {
    // Count policies, not files: a directory of `.cedar` files that are all
    // comments, whitespace or templates yields exactly the deny-everything set
    // this guard exists to refuse. A genuine deny-all is written explicitly as
    // `forbid (principal, action, resource);`.
    if set.num_of_policies() == 0 {
        return Err(PolicyLoadError::Empty {
            path: source.to_path_buf(),
        });
    }

    let result = Validator::new(schema.clone()).validate(&set, ValidationMode::Strict);
    if !result.validation_passed() {
        return Err(PolicyLoadError::Validation {
            errors: result.validation_errors().map(|e| e.to_string()).collect(),
        });
    }
    for w in result.validation_warnings() {
        tracing::warn!(warning = %w, "cedar policy validation warning");
    }
    for lint in lint_arg_matching(&set) {
        tracing::warn!(lint = %lint, "cedar policy lint");
    }

    Ok(LoadedPolicies {
        set,
        generation,
        loaded_at: SystemTime::now(),
        files,
    })
}

pub struct Engine {
    schema: Schema,
    policy_dir: PathBuf,
    current: ArcSwap<LoadedPolicies>,
}

impl Engine {
    /// Load the initial policy set. Fails fast: a daemon that cannot load valid
    /// policies must not start.
    pub fn bootstrap(schema: Schema, policy_dir: PathBuf) -> Result<Self, PolicyLoadError> {
        let initial = load_dir(&policy_dir, &schema, 1)?;
        Ok(Self {
            schema,
            policy_dir,
            current: ArcSwap::from_pointee(initial),
        })
    }

    /// Build an engine around a policy set assembled in memory — a set derived from
    /// the shipped pack, say — through the same guards [`load_dir`] applies: a
    /// zero-policy set is refused, the set is strict-validated against `schema`, and
    /// the load lints are logged. `policy_dir` is what `/healthz` reports and what
    /// [`Engine::reload`] will read, so a reload replaces the in-memory set with
    /// whatever that directory holds.
    pub fn from_policy_set(
        schema: Schema,
        policy_dir: PathBuf,
        set: PolicySet,
        generation: u64,
    ) -> Result<Self, PolicyLoadError> {
        let loaded = checked(set, &schema, &policy_dir, generation, Vec::new())?;
        Ok(Self {
            schema,
            policy_dir,
            current: ArcSwap::from_pointee(loaded),
        })
    }

    /// Build an engine around an already-loaded set, **skipping every guard**.
    ///
    /// `#[cfg(test)]` on purpose: this is the only way to put an engine in the
    /// zero-policy state, which `bootstrap`, `from_policy_set` and `reload` all
    /// refuse, and the HTTP layer's "no policies loaded" 503 — the only signal that
    /// separates a broken decider from a policy denial — cannot be exercised
    /// otherwise. It was public until the deviations audit pointed out that a
    /// production caller could then construct the one state the daemon is designed
    /// never to hold, so the branch's test moved into `crate::server`'s unit tests
    /// to keep this seam out of the shipped API.
    #[cfg(test)]
    pub(crate) fn from_loaded_unchecked(
        schema: Schema,
        policy_dir: PathBuf,
        loaded: LoadedPolicies,
    ) -> Self {
        Self {
            schema,
            policy_dir,
            current: ArcSwap::from_pointee(loaded),
        }
    }

    pub fn snapshot(&self) -> Arc<LoadedPolicies> {
        self.current.load_full()
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    pub fn policy_dir(&self) -> &Path {
        &self.policy_dir
    }

    /// Evaluate a query. Never returns an error: every failure path is a deny
    /// with a reason, because nono is waiting on a decision.
    pub fn evaluate(&self, q: &crate::query::PolicyQuery) -> crate::decision::Decision {
        use crate::decision::Decision;

        let started = std::time::Instant::now();

        // Endpoint paths arrive exactly as the client sent them: not normalised,
        // still percent-encoded. A policy matching `resource.path` is therefore
        // matching a string whose meaning depends on the upstream's own
        // normalisation rules, and a prefix glob like `path like "/repos/*"` is
        // satisfied by `/repos/../user/keys`. Normalising here would silently change
        // what policy sees and would guess at those rules, so the path stays raw and
        // an ambiguous one is refused instead — before any policy is consulted, so no
        // permit can be credited for it. See `crate::endpoint_path`.
        if let crate::query::Target::Endpoint { path, .. } = &q.target {
            if let Some(ambiguity) = crate::endpoint_path::ambiguity(path) {
                let reason = format!(
                    "ambiguous endpoint path {path:?}: {} — refusing to guess what the \
                     upstream resolves it to",
                    ambiguity.describe()
                );
                let decision = Decision::deny(reason);
                tracing::warn!(
                    request_id = %crate::sanitize::control_escape(&q.request_id),
                    reason = %decision.reason,
                    "denying an endpoint request whose path is ambiguous"
                );
                return decision;
            }
        }

        let (request, entities) = match crate::cedar::entities::build(q, &self.schema) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(error = %e, "failed to build cedar request; denying");
                return Decision::deny(format!("could not build policy request: {e}"));
            }
        };

        let snapshot = self.snapshot();
        let response =
            cedar_policy::Authorizer::new().is_authorized(&request, &snapshot.set, &entities);
        Decision::from_response(&response, started.elapsed().as_micros())
    }

    /// Swap in a freshly loaded set. On any error the current set is retained
    /// (spec D7: a bad edit mid-session must not brick a running agent).
    pub fn reload(&self) -> Result<u64, PolicyLoadError> {
        let next_gen = self.snapshot().generation + 1;
        let loaded = load_dir(&self.policy_dir, &self.schema, next_gen)?;
        let count = loaded.set.num_of_policies();
        self.current.store(Arc::new(loaded));
        tracing::info!(
            generation = next_gen,
            policies = count,
            "policy set reloaded"
        );
        Ok(next_gen)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
@id("allow-git")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" };

forbid (principal, action == Nono::Action::"launchCommand", resource)
when { resource.args.contains("--force") };
"#;

    fn dir_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (name, body) in files {
            std::fs::write(d.path().join(name), body).unwrap();
        }
        d
    }

    #[test]
    fn loads_policies_with_provenance_ids() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("git.cedar", GOOD)]);
        let loaded = load_dir(d.path(), &schema, 1).unwrap();
        let mut ids: Vec<String> = loaded.set.policies().map(|p| p.id().to_string()).collect();
        ids.sort();
        assert_eq!(ids, vec!["git:1".to_string(), "git:allow-git".to_string()]);
        assert_eq!(loaded.generation, 1);
        assert_eq!(loaded.files.len(), 1);
    }

    #[test]
    fn ignores_non_cedar_files() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("git.cedar", GOOD), ("README.md", "not a policy")]);
        let loaded = load_dir(d.path(), &schema, 1).unwrap();
        assert_eq!(loaded.files.len(), 1);
    }

    #[test]
    fn empty_dir_is_an_error_not_a_deny_everything_daemon() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(
            load_dir(d.path(), &schema, 1),
            Err(PolicyLoadError::Empty { .. })
        ));
    }

    /// The zero-policy guard has to be a property of *construction*, not of one
    /// entry point: an `Engine` holding an empty set answers every request from the
    /// 503 branch, i.e. "the decider is broken", and if that branch were ever
    /// simplified away it would answer deny-everything while `/healthz` looked fine.
    /// So the only constructor a caller outside this crate can reach — a set
    /// assembled in memory rather than read from a directory — runs exactly the
    /// guards `load_dir` runs: non-empty, and strict-validated against the schema.
    #[test]
    fn the_public_in_memory_constructor_applies_the_load_guards() {
        let schema = crate::cedar::schema::load().unwrap();
        let dir = PathBuf::from("/nonexistent/policies");

        let refused =
            Engine::from_policy_set(schema.clone(), dir.clone(), PolicySet::new(), 1).err();
        assert!(
            matches!(refused, Some(PolicyLoadError::Empty { .. })),
            "an empty set denies everything and must be refused, got {refused:?}"
        );

        let off_schema = PolicySet::from_str(
            r#"permit (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.cwd == "/" };"#,
        )
        .unwrap();
        let refused = Engine::from_policy_set(schema.clone(), dir.clone(), off_schema, 1).err();
        assert!(
            matches!(refused, Some(PolicyLoadError::Validation { .. })),
            "a set that does not validate must not become the active one, got {refused:?}"
        );

        let engine =
            Engine::from_policy_set(schema, dir, PolicySet::from_str(GOOD).unwrap(), 7).unwrap();
        assert_eq!(engine.snapshot().generation, 7);
        assert_eq!(engine.snapshot().set.num_of_policies(), 2);
    }

    /// A directory full of `.cedar` files that yield *no policies* is exactly the
    /// deny-everything set the Empty guard exists to refuse. Counting files
    /// instead of policies lets it through.
    #[test]
    fn cedar_files_containing_no_policies_are_refused() {
        let schema = crate::cedar::schema::load().unwrap();
        let cases = [
            (
                "comments only",
                "// every policy in here is commented out\n",
            ),
            ("whitespace only", "   \n\t\n"),
            (
                "templates only",
                "@id(\"t\")\npermit (principal == ?principal, action, resource);\n",
            ),
        ];
        for (label, body) in cases {
            let d = dir_with(&[("10-git.cedar", body)]);
            let err = load_dir(d.path(), &schema, 1).unwrap_err();
            assert!(
                matches!(err, PolicyLoadError::Empty { .. }),
                "{label}: a zero-policy set denies everything and must be refused, got {err}"
            );
        }
    }

    /// D7 inverts if an empty set is allowed to become the last known good one:
    /// every later failed reload would then retain deny-everything.
    #[test]
    fn reload_refuses_an_emptied_policy_set_and_keeps_the_last_good_one() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("git.cedar", GOOD)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();
        std::fs::write(
            d.path().join("git.cedar"),
            "// oops, commented out the lot\n",
        )
        .unwrap();

        let err = engine.reload().unwrap_err();
        assert!(matches!(err, PolicyLoadError::Empty { .. }), "{err}");
        assert_eq!(
            engine.snapshot().generation,
            1,
            "generation must not advance"
        );
        assert_eq!(engine.snapshot().set.num_of_policies(), 2);
        assert!(
            engine
                .evaluate(&command_query(
                    "session",
                    "git",
                    &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"]
                ))
                .allow,
            "an emptied reload must not become the active set"
        );
    }

    /// While a policy file is open in an editor the directory can hold lock
    /// symlinks and backups. Those must not abort the load — a reload that fails
    /// for the whole duration of an editing session is a self-inflicted outage.
    #[test]
    fn editor_sidecars_and_cedar_named_directories_are_ignored() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("10-git.cedar", GOOD), ("10-git.cedar~", GOOD)]);
        // Emacs's lock file is a dangling symlink named `.#<file>`.
        std::os::unix::fs::symlink("ac@host.12345:1", d.path().join(".#10-git.cedar")).unwrap();
        std::fs::create_dir(d.path().join("archive.cedar")).unwrap();

        let loaded = load_dir(d.path(), &schema, 1).unwrap();
        assert_eq!(loaded.files, vec![d.path().join("10-git.cedar")]);
        assert_eq!(loaded.set.num_of_policies(), 2);
    }

    /// Skipping is right; skipping *silently* is not. A `.cedar` file the loader
    /// passes over is a policy the operator wrote and the daemon is not enforcing —
    /// `.baseline.cedar` (a name a dotfile-minded author reaches for, or a partial
    /// `mv`) governs nothing, and a `forbid` among them is a hole. The operator has
    /// only the log to learn from, so every skip has to appear in it, at WARN, with
    /// the path and the reason.
    #[test]
    fn every_skipped_cedar_file_is_named_in_the_log() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("10-git.cedar", GOOD), (".baseline.cedar", GOOD)]);
        std::fs::create_dir(d.path().join("archive.cedar")).unwrap();
        // Emacs's lock file is a dangling symlink named `.#<file>` — the shape
        // that sits in a policy directory for the whole of an editing session.
        std::os::unix::fs::symlink("ac@host.12345:1", d.path().join(".#10-git.cedar")).unwrap();

        let (loaded, log) =
            crate::test_log::with_captured_log(|| load_dir(d.path(), &schema, 1).unwrap());

        assert_eq!(loaded.files, vec![d.path().join("10-git.cedar")]);
        assert!(
            log.contains(".baseline.cedar"),
            "a hidden policy file must be named in the log: {log:?}"
        );
        assert!(
            log.contains("archive.cedar"),
            "a .cedar path that is not a regular file must be named: {log:?}"
        );
        assert!(
            log.contains(".#10-git.cedar"),
            "an editor lock file must be named in the log too: {log:?}"
        );
        assert!(
            log.lines()
                .filter(|l| l.contains("WARN") && l.contains("skipping"))
                .count()
                >= 3,
            "every skip must be WARN, not a level an operator filters out: {log:?}"
        );
        assert!(
            log.contains("not loaded"),
            "the line must say the file is not in force: {log:?}"
        );
        // `/10-git.cedar` and not the bare name: the lock file's path legitimately
        // ends `.#10-git.cedar`, which contains the loaded file's name as a
        // substring.
        assert!(
            !log.contains("/10-git.cedar"),
            "a file that WAS loaded must not be reported as skipped: {log:?}"
        );
    }

    /// An entry the listing itself fails to yield must fail the load, never be
    /// silently dropped: the loader cannot classify what it could not read, so it
    /// cannot know the entry was not a policy — and an unreadable entry in a
    /// policy directory is the shape of a tampering symptom. Injected through the
    /// seam because a real `read_dir` entry error cannot be produced hermetically;
    /// the error is the *directory's* (enumeration), distinguishable from the
    /// per-file `ReadFile` error, or the operator debugs the wrong thing.
    #[test]
    fn an_unenumerable_directory_entry_fails_the_load_naming_the_directory() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("git.cedar", GOOD)]);
        let listing = [
            Ok(d.path().join("git.cedar")),
            Err(std::io::Error::other("Input/output error")),
        ];

        let err = load_entries(d.path(), listing, &schema, 1).unwrap_err();
        assert!(matches!(err, PolicyLoadError::Io { .. }), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("reading policy dir"),
            "the failure belongs to enumeration, not to a named file: {text}"
        );
        assert!(
            text.contains(&d.path().display().to_string()),
            "the directory must be named: {text}"
        );
        assert!(
            !text.contains("reading policy file"),
            "an enumeration failure must not read as a per-file one: {text}"
        );
    }

    /// A per-file read failure is not a directory read failure; the message has
    /// to say which is which or the operator debugs the wrong thing.
    #[test]
    fn an_unreadable_policy_file_is_reported_as_a_file_error() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = tempfile::tempdir().unwrap();
        // Invalid UTF-8 fails read_to_string without needing permission games.
        std::fs::write(d.path().join("bad.cedar"), [0x70, 0x65, 0xff, 0xfe]).unwrap();
        let err = load_dir(d.path(), &schema, 1).unwrap_err();
        assert!(matches!(err, PolicyLoadError::ReadFile { .. }), "{err}");
        let text = err.to_string();
        assert!(text.contains("reading policy file"), "{text}");
        assert!(text.contains("bad.cedar"), "{text}");
    }

    /// `argv_tail` is a space-join, so an **unanchored** glob over it also matches
    /// text *inside* a single argument. Over-matching is fail-safe in a `forbid` and
    /// unsound in a `permit`, so an unanchored pattern in a permit gets flagged.
    /// This is the hazard that SURVIVES the removal of `argv`: flattening, not
    /// anchoring.
    #[test]
    fn an_unanchored_argv_tail_permit_is_linted_but_a_forbid_is_not() {
        let forbid_tail = r#"@id("no-force")
forbid (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail like "*--force*" };"#;
        assert!(lint_arg_matching(&PolicySet::from_str(forbid_tail).unwrap()).is_empty());

        let permit_tail = r#"@id("git-push")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail like "*push*" };"#;
        let set = PolicySet::from_str(permit_tail).unwrap();
        let lints = lint_arg_matching(&set);
        assert_eq!(lints.len(), 1, "{lints:?}");
        assert!(lints[0].contains("argv_tail"), "{lints:?}");
        assert!(lints[0].contains("anchor"), "{lints:?}");
        // The operator has to be told *which* policy: the loader assigns
        // `<file stem>:<@id>` ids, so naming the id names the file too.
        let id = set.policies().next().unwrap().id().to_string();
        assert!(lints[0].contains(&id), "{lints:?}");

        // A comment that merely mentions argv_tail is not a read of it.
        let clean = r#"@id("ok")
// an unanchored argv_tail glob is forbid-only, so this uses args
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.args.contains("status") };"#;
        assert!(lint_arg_matching(&PolicySet::from_str(clean).unwrap()).is_empty());
    }

    /// The reason `argv_tail` exists: it is the only way to say "the subcommand is
    /// FIRST", which set membership cannot express. A pattern anchored at the start —
    /// or an equality test — is a positional pin, not an over-matching substring
    /// search, so it is the sound shape for a `permit` and must not be linted. The
    /// shipped read-only git permit has exactly this shape.
    #[test]
    fn a_positionally_anchored_argv_tail_permit_is_not_linted() {
        for body in [
            r#"@id("git-status")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail == "status" };"#,
            r#"@id("git-status-args")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail like "status *" };"#,
            r#"@id("git-read-only")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" &&
       (resource.argv_tail == "status" || resource.argv_tail like "status *" ||
        resource.argv_tail == "log" || resource.argv_tail like "log *") };"#,
        ] {
            let lints = lint_arg_matching(&PolicySet::from_str(body).unwrap());
            assert!(lints.is_empty(), "{body}\ngot {lints:?}");
        }

        // One unanchored read among anchored ones is still flagged: the unanchored
        // half is what can over-match into an approval.
        let mixed = r#"@id("mixed")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail like "status *" || resource.argv_tail like "*--porcelain*" };"#;
        assert_eq!(
            lint_arg_matching(&PolicySet::from_str(mixed).unwrap()).len(),
            1
        );

        // Anything that is neither an anchored pattern nor an equality test is not a
        // positional pin, so it stays flagged — a negated test in a permit widens it.
        let negated = r#"@id("not-status")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail != "push" };"#;
        assert_eq!(
            lint_arg_matching(&PolicySet::from_str(negated).unwrap()).len(),
            1
        );
    }

    /// Anchoring is not enough on its own: the literal has to end where the token
    /// ends. `like "diff*"` pins position but not the *whole* subcommand, so it also
    /// approves `git difftool --extcmd=<cmd>` — which executes `<cmd>`. A pin that
    /// stops mid-token is the same class of over-match the lint exists for.
    #[test]
    fn an_anchored_permit_that_stops_mid_token_is_linted() {
        for body in [
            r#"@id("diff-prefix")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail like "diff*" };"#,
            r#"@id("status-prefix")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail like "status--*" };"#,
        ] {
            let lints = lint_arg_matching(&PolicySet::from_str(body).unwrap());
            assert_eq!(lints.len(), 1, "{body}\ngot {lints:?}");
            assert!(lints[0].contains("token"), "{lints:?}");
        }

        // A pattern with no wildcard at all is an exact test, so it pins the token by
        // construction and is not flagged.
        let exact = r#"@id("exact")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail like "status" };"#;
        assert!(lint_arg_matching(&PolicySet::from_str(exact).unwrap()).is_empty());
    }

    /// The residual form of the fail-open bug: `args` still holds the per-run shim
    /// path, so a literal that looks like a command path can never match it. In a
    /// `forbid` that is fail-open, so the lint covers both effects.
    #[test]
    fn an_args_membership_test_against_a_path_literal_is_linted() {
        for body in [
            r#"@id("block-shim")
forbid (principal, action == Nono::Action::"launchCommand", resource)
when { resource.args.contains("/usr/bin/git") };"#,
            r#"@id("allow-shim")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.args.contains("/private/tmp/nono-tool-sandbox-1-2-3/shims/git") };"#,
            r#"@id("any-shim")
forbid (principal, action == Nono::Action::"launchCommand", resource)
when { resource.args.containsAny(["/bin/sh", "--force"]) };"#,
        ] {
            let lints = lint_arg_matching(&PolicySet::from_str(body).unwrap());
            assert_eq!(lints.len(), 1, "{body}\ngot {lints:?}");
            assert!(lints[0].contains("resource.command"), "{lints:?}");
        }

        // A flag or subcommand carries no `/`, so the common case stays quiet.
        let clean = r#"@id("ok")
forbid (principal, action == Nono::Action::"launchCommand", resource)
when { resource.args.contains("--force") };"#;
        assert!(lint_arg_matching(&PolicySet::from_str(clean).unwrap()).is_empty());
    }

    /// The lint that used to guard anchored `argv` patterns is replaced by a
    /// structural guarantee: `argv` is not in the schema, so a policy that reads
    /// it is refused at load. An operator cannot ignore this the way a warning
    /// can be ignored.
    #[test]
    fn a_policy_reading_argv_is_refused_at_load() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[(
            "30-anchor.cedar",
            r#"@id("block-commit")
forbid (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv like "git commit *" };"#,
        )]);
        let err = load_dir(d.path(), &schema, 1).unwrap_err();
        assert!(matches!(err, PolicyLoadError::Validation { .. }), "{err}");
    }

    /// End to end over the shape nono really sends: an anchored `forbid` fires
    /// against `argv_tail` and the shim path in `args[0]` cannot suppress it.
    #[test]
    fn an_anchored_forbid_fires_against_the_runtime_payload_via_argv_tail() {
        let schema = crate::cedar::schema::load().unwrap();
        let body = r#"
@id("permit-git")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" };

@id("no-commit")
forbid (principal, action == Nono::Action::"launchCommand", resource)
when { resource.argv_tail like "commit *" };
"#;
        let d = dir_with(&[("30-anchor.cedar", body)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();

        let denied = engine.evaluate(&command_query(
            "session",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "commit", "--amend"],
        ));
        assert!(
            !denied.allow,
            "the anchored forbid must fire on the real payload: {denied:?}"
        );
        assert!(
            denied.matched.contains(&"30-anchor:no-commit".to_string()),
            "{denied:?}"
        );

        let allowed = engine.evaluate(&command_query(
            "session",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
        ));
        assert!(allowed.allow, "{allowed:?}");
    }

    #[test]
    fn syntax_error_reports_the_file() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("broken.cedar", "permit (this is not cedar")]);
        let err = load_dir(d.path(), &schema, 1).unwrap_err();
        assert!(err.to_string().contains("broken.cedar"), "{err}");
    }

    #[test]
    fn schema_violation_fails_validation() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[(
            "bad.cedar",
            r#"permit (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.cwd == "/tmp" };"#,
        )]);
        let err = load_dir(d.path(), &schema, 1).unwrap_err();
        assert!(matches!(err, PolicyLoadError::Validation { .. }), "{err}");
    }

    #[test]
    fn duplicate_ids_in_one_file_fail_loudly() {
        let schema = crate::cedar::schema::load().unwrap();
        let body = r#"
@id("same")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" };

@id("same")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "gh" };
"#;
        let d = dir_with(&[("dup.cedar", body)]);
        let err = load_dir(d.path(), &schema, 1).unwrap_err();
        assert!(matches!(err, PolicyLoadError::Duplicate { .. }), "{err}");
        // The variant is not the requirement: the operator has to be told which file
        // to go and edit, so the message itself is asserted. Dropping `path` from the
        // Display impl would otherwise keep this test green.
        let text = err.to_string();
        assert!(text.contains("dup.cedar"), "must name the file: {text}");
        assert!(
            text.contains("dup:same"),
            "must name the duplicated id: {text}"
        );
    }

    #[test]
    fn bootstrap_exposes_a_snapshot() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("git.cedar", GOOD)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();
        assert_eq!(engine.snapshot().generation, 1);
        assert_eq!(engine.snapshot().set.num_of_policies(), 2);
    }

    use crate::query::{CallerKind, PolicyQuery, Target};

    fn command_query(caller: &str, command: &str, args: &[&str]) -> PolicyQuery {
        PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "s1".to_string(),
            caller: caller.to_string(),
            caller_kind: if caller == "session" {
                CallerKind::Session
            } else {
                CallerKind::Command
            },
            request_id: "r1".to_string(),
            backend: "cedar".to_string(),
            reason: None,
            target: Target::Command {
                command: command.to_string(),
                args: args.iter().map(|a| a.to_string()).collect(),
                intercept_rule: "rule".to_string(),
                child_pid: 42,
            },
        }
    }

    fn endpoint_query(method: &str, path: &str) -> PolicyQuery {
        PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "proxy".to_string(),
            caller: "proxy".to_string(),
            caller_kind: CallerKind::Session,
            request_id: "p1".to_string(),
            backend: "cedar".to_string(),
            reason: None,
            target: Target::Endpoint {
                route_id: "github-api".to_string(),
                upstream: "https://api.github.com".to_string(),
                method: method.to_string(),
                path: path.to_string(),
                rule_label: "rl".to_string(),
                child_pid: 0,
            },
        }
    }

    const MATRIX: &str = r#"
@id("allow-git")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"launchCommand",
  resource
) when { resource.command == "git" && !resource.args.contains("--force") };

@id("session-only")
forbid (principal, action == Nono::Action::"launchCommand", resource)
unless { principal == Nono::Caller::"session" };

@id("allow-github-reads")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"httpRequest",
  resource
) when { resource.method == "GET" && resource.path like "/repos/*" };
"#;

    fn matrix_engine() -> (Engine, tempfile::TempDir) {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("matrix.cedar", MATRIX)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();
        (engine, d)
    }

    #[test]
    fn allows_a_permitted_command() {
        let (engine, _d) = matrix_engine();
        let decision = engine.evaluate(&command_query(
            "session",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
        ));
        assert!(decision.allow, "{decision:?}");
        assert_eq!(decision.matched, vec!["matrix:allow-git".to_string()]);
        assert!(
            decision.reason.contains("matrix:allow-git"),
            "{}",
            decision.reason
        );
    }

    #[test]
    fn denies_when_a_forbid_matches() {
        let (engine, _d) = matrix_engine();
        let decision = engine.evaluate(&command_query(
            "npm",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
        ));
        assert!(!decision.allow);
        assert!(decision.matched.iter().any(|m| m.ends_with("session-only")));
        assert!(
            decision.reason.contains("session-only"),
            "{}",
            decision.reason
        );
    }

    #[test]
    fn denies_with_default_deny_reason_when_nothing_matches() {
        let (engine, _d) = matrix_engine();
        let decision = engine.evaluate(&command_query(
            "session",
            "curl",
            &[
                "/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/curl",
                "evil.example",
            ],
        ));
        assert!(!decision.allow);
        assert!(decision.matched.is_empty());
        assert!(
            decision.reason.contains("no policy"),
            "empty reason set needs explicit default-deny text, got {}",
            decision.reason
        );
    }

    #[test]
    fn unmapped_agent_is_denied() {
        let (engine, _d) = matrix_engine();
        let mut q = command_query(
            "session",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
        );
        q.agent = "unknown".to_string();
        assert!(!engine.evaluate(&q).allow);
    }

    #[test]
    fn evaluates_endpoint_requests() {
        let (engine, _d) = matrix_engine();
        assert!(
            engine
                .evaluate(&endpoint_query("GET", "/repos/foo/bar"))
                .allow
        );
        assert!(
            !engine
                .evaluate(&endpoint_query("DELETE", "/repos/foo/bar"))
                .allow
        );
    }

    /// nono sends the raw, unnormalised, still-percent-encoded path, so the prefix
    /// glob the design and the docs use — `resource.path like "/repos/*"` — is
    /// satisfied by a path a normalising upstream resolves to `/user/keys`. The path
    /// stays raw for the policies that match it; an *ambiguous* one is refused
    /// before any policy is consulted, so no permit can be credited for it.
    #[test]
    fn an_ambiguous_endpoint_path_is_denied_before_any_policy_is_consulted() {
        let (engine, _d) = matrix_engine();
        for path in [
            "/repos/../user/keys",
            "/repos/%2e%2e/user/keys",
            "/repos/%2E%2e/user/keys",
            "/repos/%252e%252e/user/keys",
            "/repos/..;/user/keys",
            "/repos//../user/emails",
            "/repos/%zz/foo",
        ] {
            let decision = engine.evaluate(&endpoint_query("GET", path));
            assert!(
                !decision.allow,
                "{path} must not satisfy a /repos/* permit: {decision:?}"
            );
            assert!(
                decision.matched.is_empty(),
                "no policy may be credited for {path}: {decision:?}"
            );
            assert!(
                decision.reason.contains("ambiguous endpoint path"),
                "the reason must name the ambiguity, got {}",
                decision.reason
            );
            assert!(
                decision.reason.contains(path),
                "the reason must name the path, got {}",
                decision.reason
            );
        }

        // The guard is about endpoint paths only: `..` in a command argument is an
        // ordinary relative path and must still be decided by policy.
        assert!(
            engine
                .evaluate(&command_query(
                    "session",
                    "git",
                    &[crate::wire::EXAMPLE_SHIM_ARGV0, "diff", "../sibling"]
                ))
                .allow,
            "a command argument containing .. must not be caught by the path guard"
        );
    }

    /// `caller_kind` exists so a policy can tell a direct agent launch from one
    /// chained through another intercepted command. The shipped pack expresses that
    /// through the principal, so this is the test that the *context* string is
    /// usable — a policy reads `"session"`/`"command"`, not a Rust enum.
    #[test]
    fn a_policy_can_decide_on_the_caller_kind_context() {
        let schema = crate::cedar::schema::load().unwrap();
        let body = r#"
@id("direct-launches-only")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { context.caller_kind == "session" && resource.command == "git" };
"#;
        let d = dir_with(&[("kind.cedar", body)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();

        let direct = engine.evaluate(&command_query(
            "session",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
        ));
        assert!(direct.allow, "{direct:?}");
        assert_eq!(
            direct.matched,
            vec!["kind:direct-launches-only".to_string()]
        );

        let chained = engine.evaluate(&command_query(
            "npm",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
        ));
        assert!(
            !chained.allow,
            "a chained launch presents caller_kind \"command\", so the permit must \
             not fire: {chained:?}"
        );
        assert!(chained.matched.is_empty(), "{chained:?}");
    }

    #[test]
    fn records_evaluation_time() {
        let (engine, _d) = matrix_engine();
        let decision = engine.evaluate(&command_query(
            "session",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
        ));
        assert!(decision.eval_us > 0);
    }

    /// Upstream embeds the intercepted command's name in `request_id`, so bytes
    /// an attacker chose reach the entity uid. The decision must stay a deny and
    /// the reason must not smuggle terminal escapes into the operator's log.
    #[test]
    fn control_bytes_in_an_identifier_cannot_inject_into_the_deny_reason() {
        let (engine, _d) = matrix_engine();
        let mut q = command_query(
            "session",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
        );
        q.request_id = "approve-git\u{1b}[2K\rDENY OVERRIDDEN: decision=allow".to_string();
        let decision = engine.evaluate(&q);
        assert!(!decision.allow, "{decision:?}");
        assert!(
            !decision.reason.chars().any(char::is_control),
            "raw control bytes in the reason: {:?}",
            decision.reason
        );
        assert!(decision.reason.contains("\\u{001b}"), "{}", decision.reason);
    }

    /// A `forbid` that errors at evaluation time is skipped by Cedar, so the
    /// remaining `permit` yields Allow. We must not trust that Allow.
    ///
    /// The setup is pinned as well as the outcome: Cedar's own decision here has to
    /// *be* `Allow`, otherwise the test degenerates into observing an ordinary deny
    /// and stops covering the override at all — which is what would happen if a
    /// later Cedar release stopped evaluating the permit, or if the overflow moved
    /// into the permit instead.
    #[test]
    fn evaluation_errors_force_a_deny_even_when_cedar_says_allow() {
        let schema = crate::cedar::schema::load().unwrap();
        let body = r#"
@id("permit-git")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" };

@id("overflowing-forbid")
forbid (principal, action == Nono::Action::"launchCommand", resource)
when { resource.arg_count + 9223372036854775807 > 0 };
"#;
        let d = dir_with(&[("boom.cedar", body)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();
        let query = command_query(
            "session",
            "git",
            &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
        );

        // What Cedar itself says about this request, before our fail-closed rule.
        let (request, entities) = crate::cedar::entities::build(&query, engine.schema()).unwrap();
        let raw = cedar_policy::Authorizer::new().is_authorized(
            &request,
            &engine.snapshot().set,
            &entities,
        );
        assert_eq!(
            raw.decision(),
            cedar_policy::Decision::Allow,
            "the WHEN of this scenario is an allow *with* errors; Cedar no longer \
             produces one, so this test would otherwise pass on a plain deny"
        );
        let errors: Vec<String> = raw.diagnostics().errors().map(|e| e.to_string()).collect();
        assert!(
            errors.iter().any(|e| e.contains("overflowing-forbid")),
            "the skipped policy must be the forbid: {errors:?}"
        );

        let decision = engine.evaluate(&query);
        assert!(
            !decision.allow,
            "an errored forbid must not be silently skipped: {decision:?}"
        );
        assert!(
            decision.reason.contains("evaluation error"),
            "{}",
            decision.reason
        );
        assert_eq!(
            decision.matched,
            vec!["boom:permit-git".to_string()],
            "the overridden allow is still on the record, so an operator can see \
             which permit would have fired: {decision:?}"
        );
    }

    #[test]
    fn reload_picks_up_edits_and_bumps_generation() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("p.cedar", MATRIX)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();
        assert!(
            engine
                .evaluate(&command_query(
                    "session",
                    "git",
                    &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"]
                ))
                .allow
        );

        std::fs::write(
            d.path().join("p.cedar"),
            r#"forbid (principal, action, resource);"#,
        )
        .unwrap();
        let generation = engine.reload().unwrap();
        assert_eq!(generation, 2);
        assert!(
            !engine
                .evaluate(&command_query(
                    "session",
                    "git",
                    &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"]
                ))
                .allow
        );
    }

    #[test]
    fn failed_reload_keeps_last_good_policies() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("p.cedar", MATRIX)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();

        std::fs::write(d.path().join("p.cedar"), "permit (this is not cedar").unwrap();
        assert!(engine.reload().is_err());

        assert_eq!(
            engine.snapshot().generation,
            1,
            "generation must not advance"
        );
        assert!(
            engine
                .evaluate(&command_query(
                    "session",
                    "git",
                    &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"]
                ))
                .allow,
            "a broken edit must not brick a running agent"
        );
    }

    /// The directory-level shape of the enumeration failure — the only one a
    /// hermetic test can produce at reload, since a per-entry error needs the
    /// injection seam above. Retention is the existing machinery: `reload`
    /// returns the error, the last-good set keeps deciding, and the error names
    /// the directory so the operator debugs enumeration, not a file.
    #[test]
    fn a_reload_that_cannot_enumerate_the_directory_keeps_the_last_good_set() {
        use std::os::unix::fs::PermissionsExt;
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("p.cedar", MATRIX)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();

        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
        let err = engine.reload().unwrap_err();
        // Restore before asserting so the tempdir can clean up after itself.
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(err, PolicyLoadError::Io { .. }), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("reading policy dir"),
            "an enumeration failure, not a per-file one: {text}"
        );
        assert!(
            text.contains(&d.path().display().to_string()),
            "the directory must be named: {text}"
        );
        assert_eq!(
            engine.snapshot().generation,
            1,
            "generation must not advance"
        );
        assert!(
            engine
                .evaluate(&command_query(
                    "session",
                    "git",
                    &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"]
                ))
                .allow,
            "the last-good set must keep deciding"
        );
    }

    #[test]
    fn failed_reload_on_schema_violation_keeps_last_good() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("p.cedar", MATRIX)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();

        std::fs::write(
            d.path().join("p.cedar"),
            r#"permit (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.cwd == "/tmp" };"#,
        )
        .unwrap();
        assert!(matches!(
            engine.reload(),
            Err(PolicyLoadError::Validation { .. })
        ));
        assert_eq!(
            engine.snapshot().generation,
            1,
            "generation must not advance"
        );
        assert!(
            engine
                .evaluate(&command_query(
                    "session",
                    "git",
                    &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"]
                ))
                .allow
        );
    }
}
