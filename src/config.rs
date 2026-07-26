//! Operator configuration. Strict on purpose: an unknown key is a load error,
//! because a silently ignored typo in a security daemon's config is worse than
//! a failed start.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The identity an unmapped approval-backend name resolves to. Deliberately not
/// configurable: the shipped baseline pack forbids `Nono::Agent::"unknown"` by
/// exactly this name, and a knob that renames the fallback silently disables
/// that deny (issue #25). `tests/policies.rs` asserts the shipped
/// `00-baseline.cedar` names this constant, so the two cannot drift apart.
pub const UNKNOWN_AGENT: &str = "unknown";

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
    /// Absent ⇒ plaintext, exactly as before (T2). TLS is opt-in because the
    /// shipped defaults have to start without a certificate ceremony; what is
    /// *not* optional is that a `[tls]` table which is present and broken
    /// refuses to serve rather than falling back to plaintext.
    pub tls: Option<Tls>,
}

/// The certificate and private key of the https listener.
///
/// `deny_unknown_fields` is repeated here on purpose: it does **not** recurse
/// from `Config`, so without it a typo inside `[tls]` deserializes into a struct
/// with the mistyped key silently dropped — the precise thing the strict-config
/// rule exists to prevent, one level deeper than the rule was written.
///
/// Both fields are required — no `Option`, no `default`. A `[tls]` with one half
/// is a half-configured transport, and serde's own "missing field `key`" is the
/// error the operator needs (T2).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// The leaf certificate, plus any intermediates, in PEM.
    #[serde(deserialize_with = "de_path")]
    pub cert: PathBuf,
    /// The private key in PEM. Its mode, owner and ancestor chain are checked
    /// before the daemon serves — see [`crate::isolation::refuse_a_readable_private_key`].
    #[serde(deserialize_with = "de_path")]
    pub key: PathBuf,
}

fn default_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8181))
}

fn default_audit_log() -> PathBuf {
    expand_tilde("~/.local/state/nono-cedar-pdp/decisions.jsonl")
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
    /// An unmapped name falls back to the fixed [`UNKNOWN_AGENT`] identity the
    /// shipped baseline denies, so a missing `[agents]` entry is a loud deny.
    pub fn agent_for(&self, backend: &str) -> &str {
        self.agents
            .get(backend)
            .map(String::as_str)
            .unwrap_or(UNKNOWN_AGENT)
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

    /// TLS is opt-in (T2). A config with no `[tls]` table is the shipped default
    /// posture — plaintext loopback — and must keep loading: the certificate
    /// ceremony cannot be a precondition for starting the daemon at all, or the
    /// security outcome is a daemon nobody runs.
    #[test]
    fn loads_minimal_config_with_defaults() {
        let f = write_config(r#"policy_dir = "/tmp/policies""#);
        let c = Config::load(f.path()).unwrap();
        assert_eq!(c.bind.to_string(), "127.0.0.1:8181");
        assert_eq!(c.policy_dir, std::path::Path::new("/tmp/policies"));
        assert!(c.agents.is_empty());
        assert!(
            c.tls.is_none(),
            "no [tls] table must mean no TLS configured, not a half-built one: {:?}",
            c.tls
        );
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
        assert_eq!(c.agent_for("something-else"), UNKNOWN_AGENT);
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

    /// `unknown_agent` used to rename the fallback identity an unmapped backend
    /// resolves to — which silently disabled the shipped baseline's
    /// `no-unknown-agents` forbid, because that forbid names `Agent::"unknown"`
    /// literally (issue #25). The knob is gone; a config still carrying it must
    /// fail loudly with a message that names the key, so the operator learns the
    /// setting was removed rather than having it silently ignored.
    #[test]
    fn rejects_the_removed_unknown_agent_knob() {
        let f = write_config("policy_dir = \"/tmp/p\"\nunknown_agent = \"anything\"\n");
        let err = Config::load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("unknown field `unknown_agent`"),
            "the message must name the removed key: {text}"
        );
        assert!(
            text.contains("policy_dir"),
            "and the keys that still exist: {text}"
        );
    }

    /// A `[tls]` table with only one of the pair is a half-configured transport,
    /// and T2 says a half-configured transport must not start: the operator who
    /// wrote `cert` and mistyped `key` believes the listener is authenticated.
    /// Silently ignoring the half they did write, or serving plaintext behind a
    /// profile whose URL says `https`, are both worse than a failed start.
    #[test]
    fn rejects_a_half_configured_tls_table() {
        for (half, missing) in [
            ("cert = \"/tmp/tls/cert.pem\"", "key"),
            ("key = \"/tmp/tls/key.pem\"", "cert"),
        ] {
            let f = write_config(&format!("policy_dir = \"/tmp/p\"\n\n[tls]\n{half}\n"));
            let err = Config::load(f.path()).unwrap_err();
            assert!(matches!(err, ConfigError::Parse(_)), "{half}: {err}");
            let text = err.to_string();
            assert!(
                text.contains(&format!("missing field `{missing}`")),
                "the message must name the half that is missing: {text}"
            );
        }
    }

    /// `deny_unknown_fields` does not recurse: declaring it on `Config` says
    /// nothing about a nested table, so without it on `Tls` too a typo inside
    /// `[tls]` deserializes to a struct with the mistyped key silently dropped —
    /// and then the required-pair rule above catches the wrong thing or nothing
    /// at all. The strictness rule is worth exactly as much as its reach.
    #[test]
    fn rejects_unknown_keys_inside_the_tls_table() {
        let f = write_config(
            "policy_dir = \"/tmp/p\"\n\n[tls]\ncert = \"/tmp/tls/cert.pem\"\n\
             key = \"/tmp/tls/key.pem\"\ncerificate = \"typo\"\n",
        );
        let err = Config::load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("unknown field `cerificate`"),
            "the message must name the offending key inside the table: {text}"
        );
        assert!(
            text.contains("cert"),
            "and the keys the table does define: {text}"
        );
    }

    /// nono sends no credential and cannot authenticate the decider, so the only
    /// access control this daemon has is being unreachable from other hosts. A
    /// config that removes it must not load.
    #[test]
    fn rejects_a_non_loopback_bind() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737), i.e. a documentation address:
        // an example that cannot accidentally name someone's real host.
        for bind in ["0.0.0.0:18182", "192.0.2.1:8181", "[::]:8181"] {
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

    /// The shipped `[tls]` block is written home-anchored (T8), so the tilde has
    /// to expand here for the same reason it does on `policy_dir`: an unexpanded
    /// `~` is a relative path whose meaning depends on the daemon's working
    /// directory, and the key-protection check would then walk a different chain
    /// from the one the listener reads.
    #[test]
    fn expands_tilde_in_tls_paths() {
        let f = write_config(
            "policy_dir = \"/tmp/p\"\n\n[tls]\ncert = \"~/.config/nono-cedar-pdp/tls/cert.pem\"\n\
             key = \"~/.config/nono-cedar-pdp/tls/key.pem\"\n",
        );
        let c = Config::load(f.path()).unwrap();
        let tls = c.tls.unwrap();
        for path in [&tls.cert, &tls.key] {
            assert!(path.is_absolute(), "got {path:?}");
            assert!(!path.to_string_lossy().contains('~'), "got {path:?}");
        }
    }
}
