//! Operator configuration. Strict on purpose: an unknown key is a load error,
//! because a silently ignored typo in a security daemon's config is worse than
//! a failed start.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error(
        "bind = \"{bind}\" is not a loopback address — nono sends no credential \
         and cannot authenticate the decider, so an unauthenticated PDP must not \
         be reachable from other hosts; use 127.0.0.1 or [::1]"
    )]
    NonLoopbackBind { bind: SocketAddr },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(deserialize_with = "de_path")]
    pub policy_dir: PathBuf,
    #[serde(default = "default_audit_log", deserialize_with = "de_path")]
    pub audit_log: PathBuf,
    #[serde(default)]
    pub agents: BTreeMap<String, String>,
    #[serde(default = "default_unknown_agent")]
    pub unknown_agent: String,
}

fn default_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8181))
}

fn default_audit_log() -> PathBuf {
    expand_tilde("~/.local/state/nono-cedar-pdp/decisions.jsonl")
}

fn default_unknown_agent() -> String {
    "unknown".to_string()
}

fn de_path<'de, D: serde::Deserializer<'de>>(d: D) -> Result<PathBuf, D::Error> {
    let raw = String::deserialize(d)?;
    Ok(expand_tilde(&raw))
}

/// Expand a leading `~/` using $HOME. Leaves other paths untouched.
pub fn expand_tilde(raw: &str) -> PathBuf {
    match raw.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => Path::new(&home).join(rest),
            None => PathBuf::from(raw),
        },
        None => PathBuf::from(raw),
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Config = toml::from_str(&text)?;
        // The one setting that can remove the daemon's only access control. A
        // hard error, not a warning: nothing legitimate needs the PDP reachable
        // from another host, and the mistake is invisible until someone else
        // decides your approvals.
        if !config.bind.ip().is_loopback() {
            return Err(ConfigError::NonLoopbackBind { bind: config.bind });
        }
        Ok(config)
    }

    /// Resolve the Cedar `Agent` identity for a nono approval-backend name.
    pub fn agent_for(&self, backend: &str) -> &str {
        self.agents
            .get(backend)
            .map(String::as_str)
            .unwrap_or(&self.unknown_agent)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_config(body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f
    }

    #[test]
    fn loads_minimal_config_with_defaults() {
        let f = write_config(r#"policy_dir = "/tmp/policies""#);
        let c = Config::load(f.path()).unwrap();
        assert_eq!(c.bind.to_string(), "127.0.0.1:8181");
        assert_eq!(c.policy_dir, std::path::Path::new("/tmp/policies"));
        assert_eq!(c.unknown_agent, "unknown");
        assert!(c.agents.is_empty());
    }

    #[test]
    fn maps_backend_name_to_agent_and_falls_back() {
        let f = write_config(
            r#"
policy_dir = "/tmp/policies"
[agents]
cedar = "claude-code"
"#,
        );
        let c = Config::load(f.path()).unwrap();
        assert_eq!(c.agent_for("cedar"), "claude-code");
        assert_eq!(c.agent_for("something-else"), "unknown");
    }

    /// The point of a strict schema is that a typo is loud. "Loud" is the message,
    /// not the variant: an operator who mistypes `policy_dir` needs to be told which
    /// key was rejected and which ones exist, so the text is asserted too.
    #[test]
    fn rejects_unknown_config_keys() {
        let f = write_config("policy_dir = \"/tmp/p\"\nplicy_dir = \"typo\"\n");
        let err = Config::load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("plicy_dir"),
            "the message must name the offending key: {text}"
        );
        assert!(
            text.contains("policy_dir"),
            "and the keys that do exist: {text}"
        );
    }

    /// nono sends no credential and cannot authenticate the decider, so the only
    /// access control this daemon has is being unreachable from other hosts. A
    /// config that removes it must not load.
    #[test]
    fn rejects_a_non_loopback_bind() {
        for bind in ["0.0.0.0:18182", "192.168.4.200:8181", "[::]:8181"] {
            let f = write_config(&format!("policy_dir = \"/tmp/p\"\nbind = \"{bind}\"\n"));
            let err = Config::load(f.path()).unwrap_err();
            assert!(
                matches!(err, ConfigError::NonLoopbackBind { .. }),
                "{bind}: {err}"
            );
            let text = err.to_string();
            assert!(text.contains("loopback"), "{text}");
            assert!(
                text.contains(bind),
                "the message must name the bind: {text}"
            );
        }
    }

    #[test]
    fn accepts_loopback_binds() {
        for bind in ["127.0.0.1:8181", "127.0.0.2:9000", "[::1]:8181"] {
            let f = write_config(&format!("policy_dir = \"/tmp/p\"\nbind = \"{bind}\"\n"));
            let c = Config::load(f.path()).unwrap();
            assert!(c.bind.ip().is_loopback(), "{bind}");
        }
    }

    #[test]
    fn expands_tilde_in_paths() {
        let f = write_config(r#"policy_dir = "~/policies""#);
        let c = Config::load(f.path()).unwrap();
        assert!(c.policy_dir.is_absolute(), "got {:?}", c.policy_dir);
        assert!(!c.policy_dir.to_string_lossy().contains('~'));
    }
}
