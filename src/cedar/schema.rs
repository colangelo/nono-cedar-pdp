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
    fn positional_argument_access_is_rejected_by_the_schema() {
        // `args` is a Set, so indexing is not valid Cedar against this schema.
        let schema = load().unwrap();
        let policies = PolicySet::from_str(
            r#"permit (
                 principal, action == Nono::Action::"launchCommand", resource
               ) when { resource.args.contains("push") && resource.arg_count == 2 };"#,
        )
        .unwrap();
        let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        assert!(result.validation_passed());
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
