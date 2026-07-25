//! The embedded Cedar schema. Compiled once at startup; policies are validated
//! against it at load and at every hot-reload.

use cedar_policy::Schema;

pub const SCHEMA_SRC: &str = include_str!("../../nono.cedarschema");

#[derive(Debug, thiserror::Error)]
pub enum SchemaLoadError {
    #[error("embedded Cedar schema failed to compile: {0}")]
    Compile(String),
}

pub fn load() -> Result<Schema, SchemaLoadError> {
    let (schema, warnings) = Schema::from_cedarschema_str(SCHEMA_SRC)
        .map_err(|e| SchemaLoadError::Compile(e.to_string()))?;
    for w in warnings {
        tracing::warn!(warning = %w, "cedar schema warning");
    }
    Ok(schema)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use cedar_policy::{PolicySet, ValidationMode, Validator};
    use std::str::FromStr;

    #[test]
    fn schema_compiles() {
        let schema = load().unwrap();
        let actions: Vec<String> = schema.actions().map(|a| a.to_string()).collect();
        assert!(
            actions.iter().any(|a| a.contains("launchCommand")),
            "{actions:?}"
        );
        assert!(
            actions.iter().any(|a| a.contains("httpRequest")),
            "{actions:?}"
        );
    }

    #[test]
    fn a_well_formed_policy_strict_validates() {
        let schema = load().unwrap();
        let policies = PolicySet::from_str(
            r#"permit (
                 principal in Nono::Agent::"claude-code",
                 action == Nono::Action::"launchCommand",
                 resource
               ) when { resource.command == "git" && !resource.args.contains("--force") };"#,
        )
        .unwrap();
        let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        assert!(result.validation_passed(), "{errors:#?}");
    }

    #[test]
    fn set_membership_and_arg_count_policies_validate() {
        let schema = load().unwrap();
        let policies = PolicySet::from_str(
            r#"permit (
                 principal, action == Nono::Action::"launchCommand", resource
               ) when { resource.args.contains("push") && resource.arg_count == 2 };"#,
        )
        .unwrap();
        let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        assert!(result.validation_passed(), "{errors:#?}");
    }

    /// `args` is a `Set<String>` on purpose: upstream drops non-UTF-8 argv
    /// entries, so positions shift. Index access must be unwritable, not merely
    /// discouraged — either it fails to parse or it fails validation.
    #[test]
    fn positional_argument_access_is_rejected_by_the_schema() {
        for body in [
            r#"permit (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.args[1] == "push" };"#,
            r#"permit (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.args["1"] == "push" };"#,
        ] {
            let Ok(policies) = PolicySet::from_str(body) else {
                continue; // rejected by the parser: unexpressible, as intended
            };
            let schema = load().unwrap();
            let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
            assert!(
                !result.validation_passed(),
                "index access into args must not validate: {body}"
            );
        }
    }

    /// The `argv` caveat has to live in the artifact operators read, not only in
    /// the design doc.
    #[test]
    fn the_schema_artifact_documents_the_argv_caveat() {
        assert!(
            SCHEMA_SRC.to_lowercase().contains("forbid-only"),
            "nono.cedarschema must document that argv globs belong in forbid only"
        );
    }

    #[test]
    fn unknown_attribute_fails_validation() {
        let schema = load().unwrap();
        let policies = PolicySet::from_str(
            r#"permit (
                 principal, action == Nono::Action::"launchCommand", resource
               ) when { resource.cwd == "/tmp" };"#,
        )
        .unwrap();
        let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        assert!(
            !result.validation_passed(),
            "cwd is not in the payload; policies referencing it must not validate"
        );
    }
}
