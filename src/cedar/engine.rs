//! Policy set loading, strict validation, and the hot-swappable current set.

use arc_swap::ArcSwap;
use cedar_policy::{PolicyId, PolicySet, Schema, ValidationMode, Validator};
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
    #[error("parsing {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("duplicate policy id from {path}: {message}")]
    Duplicate { path: PathBuf, message: String },
    #[error("policy validation failed against the nono schema: {}", .errors.join("; "))]
    Validation { errors: Vec<String> },
    #[error("no .cedar policies found in {path} — refusing to serve a deny-everything policy set")]
    Empty { path: PathBuf },
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
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|source| PolicyLoadError::Io {
            path: dir.to_path_buf(),
            source,
        })?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "cedar"))
        .collect();
    entries.sort();

    if entries.is_empty() {
        return Err(PolicyLoadError::Empty {
            path: dir.to_path_buf(),
        });
    }

    let mut set = PolicySet::new();
    for path in &entries {
        let text = std::fs::read_to_string(path).map_err(|source| PolicyLoadError::Io {
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

    let result = Validator::new(schema.clone()).validate(&set, ValidationMode::Strict);
    if !result.validation_passed() {
        return Err(PolicyLoadError::Validation {
            errors: result.validation_errors().map(|e| e.to_string()).collect(),
        });
    }
    for w in result.validation_warnings() {
        tracing::warn!(warning = %w, "cedar policy validation warning");
    }

    Ok(LoadedPolicies {
        set,
        generation,
        loaded_at: SystemTime::now(),
        files: entries,
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
        let decision = engine.evaluate(&command_query("session", "git", &["git", "status"]));
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
        let decision = engine.evaluate(&command_query("npm", "git", &["git", "status"]));
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
        let decision =
            engine.evaluate(&command_query("session", "curl", &["curl", "evil.example"]));
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
        let mut q = command_query("session", "git", &["git", "status"]);
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

    #[test]
    fn records_evaluation_time() {
        let (engine, _d) = matrix_engine();
        let decision = engine.evaluate(&command_query("session", "git", &["git", "status"]));
        assert!(decision.eval_us > 0);
    }

    /// A `forbid` that errors at evaluation time is skipped by Cedar, so the
    /// remaining `permit` yields Allow. We must not trust that Allow.
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
        let decision = engine.evaluate(&command_query("session", "git", &["git", "status"]));
        assert!(
            !decision.allow,
            "an errored forbid must not be silently skipped: {decision:?}"
        );
        assert!(
            decision.reason.contains("evaluation error"),
            "{}",
            decision.reason
        );
    }
}
