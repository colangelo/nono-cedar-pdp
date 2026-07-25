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
}
