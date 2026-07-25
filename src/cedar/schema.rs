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

    /// The flattened-string caveat has to live in the artifact operators read,
    /// not only in the design doc — and it now belongs to `argv_tail`, the only
    /// joined-string attribute left.
    #[test]
    fn the_schema_artifact_documents_the_argv_tail_caveat() {
        assert!(
            SCHEMA_SRC.contains("argv_tail"),
            "nono.cedarschema must declare argv_tail"
        );
        assert!(
            SCHEMA_SRC.to_lowercase().contains("forbid-only"),
            "nono.cedarschema must document that argv_tail globs belong in forbid only"
        );
        assert!(
            !SCHEMA_SRC.contains("argv:"),
            "argv must not be declared: an anchored pattern over the whole argv \
             cannot match a runtime payload, so the attribute is a fail-open \
             footgun with no sound use (D12 amendment)"
        );
    }

    /// D12 amendment: `argv` is *removed*, not deprecated. A policy that reaches
    /// for it is refused by strict validation, so the anchoring hazard is
    /// structurally unexpressible rather than merely linted — the same posture
    /// D6 takes for positional matching.
    #[test]
    fn a_policy_reading_argv_is_refused_by_strict_validation() {
        let schema = load().unwrap();
        for body in [
            r#"forbid (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.argv like "git commit *" };"#,
            r#"permit (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.argv like "*--force*" };"#,
        ] {
            let policies = PolicySet::from_str(body).unwrap();
            let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
            assert!(
                !result.validation_passed(),
                "resource.argv must not validate: {body}"
            );
        }
    }

    /// The replacement has to be usable: an anchored glob over `argv_tail` is the
    /// shape policy authors are directed to, so it must strict-validate.
    #[test]
    fn an_anchored_argv_tail_policy_strict_validates() {
        let schema = load().unwrap();
        let policies = PolicySet::from_str(
            r#"forbid (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.argv_tail like "commit *" };"#,
        )
        .unwrap();
        let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        assert!(result.validation_passed(), "{errors:#?}");
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
