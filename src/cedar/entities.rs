//! Per-request Cedar entity slices.
//!
//! Cedar keeps no cross-request state, so entity ids need only be unique within
//! one authorization call. That lets policies use short, readable ids
//! (`Nono::Caller::"session"`) while session identity lives in the parent
//! `Session` entity and in context.

use crate::query::{PolicyQuery, Target};
use cedar_policy::{Context, Entities, Entity, EntityUid, Request, RestrictedExpression, Schema};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("invalid entity uid {uid}: {message}")]
    Uid { uid: String, message: String },
    #[error("building entity: {0}")]
    Entity(String),
    #[error("building context: {0}")]
    Context(String),
    #[error("building request: {0}")]
    Request(String),
}

fn uid(text: &str) -> Result<EntityUid, BuildError> {
    EntityUid::from_str(text).map_err(|e| BuildError::Uid {
        uid: text.to_string(),
        message: e.to_string(),
    })
}

/// Cedar entity ids are quoted strings; escape `\` and `"` so a crafted command
/// name cannot break out of the literal.
fn escape(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

fn s(value: &str) -> RestrictedExpression {
    RestrictedExpression::new_string(value.to_string())
}

pub fn build(q: &PolicyQuery, schema: &Schema) -> Result<(Request, Entities), BuildError> {
    let agent = Entity::new_no_attrs(
        uid(&format!("Nono::Agent::\"{}\"", escape(&q.agent)))?,
        HashSet::new(),
    );
    let session = Entity::new_no_attrs(
        uid(&format!("Nono::Session::\"{}\"", escape(&q.session_id)))?,
        HashSet::from([agent.uid()]),
    );
    let caller_uid = uid(&format!("Nono::Caller::\"{}\"", escape(&q.caller)))?;
    let caller = Entity::new_no_attrs(caller_uid.clone(), HashSet::from([session.uid()]));

    let (action, resource, context_pairs) = match &q.target {
        Target::Command {
            command,
            args,
            intercept_rule,
            child_pid,
        } => {
            let resource_uid = uid(&format!("Nono::Command::\"{}\"", escape(&q.request_id)))?;
            let attrs = HashMap::from([
                ("command".to_string(), s(command)),
                (
                    "args".to_string(),
                    RestrictedExpression::new_set(args.iter().map(|a| s(a))),
                ),
                ("argv".to_string(), s(&args.join(" "))),
                (
                    "arg_count".to_string(),
                    RestrictedExpression::new_long(args.len() as i64),
                ),
            ]);
            let resource = Entity::new(resource_uid.clone(), attrs, HashSet::new())
                .map_err(|e| BuildError::Entity(e.to_string()))?;

            let mut pairs = vec![
                ("backend".to_string(), s(&q.backend)),
                ("intercept_rule".to_string(), s(intercept_rule)),
                ("caller_kind".to_string(), s(q.caller_kind.as_str())),
                (
                    "child_pid".to_string(),
                    RestrictedExpression::new_long(i64::from(*child_pid)),
                ),
                ("session_id".to_string(), s(&q.session_id)),
            ];
            if let Some(reason) = &q.reason {
                pairs.push(("reason".to_string(), s(reason)));
            }
            (
                uid("Nono::Action::\"launchCommand\"")?,
                (resource_uid, resource),
                pairs,
            )
        }
        Target::Endpoint {
            route_id,
            upstream,
            method,
            path,
            rule_label,
        } => {
            let resource_uid = uid(&format!(
                "Nono::HttpEndpoint::\"{}\"",
                escape(&q.request_id)
            ))?;
            let attrs = HashMap::from([
                ("route_id".to_string(), s(route_id)),
                ("upstream".to_string(), s(upstream)),
                ("method".to_string(), s(method)),
                ("path".to_string(), s(path)),
            ]);
            let resource = Entity::new(resource_uid.clone(), attrs, HashSet::new())
                .map_err(|e| BuildError::Entity(e.to_string()))?;

            let mut pairs = vec![
                ("backend".to_string(), s(&q.backend)),
                ("rule_label".to_string(), s(rule_label)),
            ];
            if let Some(reason) = &q.reason {
                pairs.push(("reason".to_string(), s(reason)));
            }
            (
                uid("Nono::Action::\"httpRequest\"")?,
                (resource_uid, resource),
                pairs,
            )
        }
    };

    let (resource_uid, resource_entity) = resource;
    let entities = Entities::from_entities([agent, session, caller, resource_entity], Some(schema))
        .map_err(|e| BuildError::Entity(e.to_string()))?;

    let context =
        Context::from_pairs(context_pairs).map_err(|e| BuildError::Context(e.to_string()))?;

    let request = Request::new(caller_uid, action, resource_uid, context, Some(schema))
        .map_err(|e| BuildError::Request(e.to_string()))?;

    Ok((request, entities))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::query::{CallerKind, PolicyQuery, Target};
    use cedar_policy::EvalResult;

    fn schema() -> Schema {
        crate::cedar::schema::load().unwrap()
    }

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
                intercept_rule: "push".to_string(),
                child_pid: 42,
            },
        }
    }

    fn endpoint_query() -> PolicyQuery {
        PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "proxy".to_string(),
            caller: "proxy".to_string(),
            caller_kind: CallerKind::Session,
            request_id: "p1".to_string(),
            backend: "cedar".to_string(),
            reason: Some("route requires approval".to_string()),
            target: Target::Endpoint {
                route_id: "github-api".to_string(),
                upstream: "https://api.github.com".to_string(),
                method: "GET".to_string(),
                path: "/repos/foo/bar".to_string(),
                rule_label: "rl".to_string(),
            },
        }
    }

    #[test]
    fn builds_the_caller_session_agent_hierarchy_for_a_command() {
        let s = schema();
        let q = command_query("session", "git", &["git", "push"]);
        let (request, entities) = build(&q, &s).unwrap();

        let principal = request.principal().unwrap();
        assert_eq!(principal.type_name().to_string(), "Nono::Caller");
        assert_eq!(principal.id().unescaped(), "session");
        assert_eq!(request.action().unwrap().id().unescaped(), "launchCommand");

        // Caller in Session in Agent, so an ancestor lookup reaches the agent.
        let session_uid = uid("Nono::Session::\"s1\"").unwrap();
        let agent_uid = uid("Nono::Agent::\"claude-code\"").unwrap();
        assert!(
            entities.get(&session_uid).is_some(),
            "session entity missing"
        );
        assert!(entities.get(&agent_uid).is_some(), "agent entity missing");

        let resource = entities.get(request.resource().unwrap()).unwrap();
        assert!(matches!(
            resource.attr("command").unwrap().unwrap(),
            EvalResult::String(ref c) if c == "git"
        ));
        assert!(matches!(
            resource.attr("argv").unwrap().unwrap(),
            EvalResult::String(ref c) if c == "git push"
        ));
        assert!(matches!(
            resource.attr("arg_count").unwrap().unwrap(),
            EvalResult::Long(2)
        ));
        assert!(resource.attr("args").unwrap().is_ok());
    }

    #[test]
    fn omits_reason_from_context_when_absent_and_includes_it_when_present() {
        let s = schema();
        let (request, _e) = build(&command_query("session", "git", &["git"]), &s).unwrap();
        let context = request.context().unwrap();
        assert!(context.get("reason").is_none(), "reason must be omitted");
        assert!(matches!(
            context.get("caller_kind").unwrap(),
            EvalResult::String(ref v) if v == "session"
        ));
        assert!(matches!(
            context.get("child_pid").unwrap(),
            EvalResult::Long(42)
        ));

        let (request, _e) = build(&endpoint_query(), &s).unwrap();
        let context = request.context().unwrap();
        assert!(matches!(
            context.get("reason").unwrap(),
            EvalResult::String(ref v) if v == "route requires approval"
        ));
    }

    #[test]
    fn builds_proxy_identity_for_an_endpoint_request() {
        let s = schema();
        let (request, entities) = build(&endpoint_query(), &s).unwrap();
        let principal = request.principal().unwrap();
        assert_eq!(principal.type_name().to_string(), "Nono::Caller");
        assert_eq!(principal.id().unescaped(), "proxy");
        assert!(entities
            .get(&uid("Nono::Session::\"proxy\"").unwrap())
            .is_some());

        let resource = entities.get(request.resource().unwrap()).unwrap();
        assert_eq!(resource.uid().type_name().to_string(), "Nono::HttpEndpoint");
        assert!(matches!(
            resource.attr("method").unwrap().unwrap(),
            EvalResult::String(ref v) if v == "GET"
        ));
        assert!(matches!(
            resource.attr("path").unwrap().unwrap(),
            EvalResult::String(ref v) if v == "/repos/foo/bar"
        ));
    }

    /// A crafted caller or command name must stay data: it may not terminate the
    /// quoted entity-id literal and inject Cedar syntax.
    #[test]
    fn crafted_names_cannot_break_out_of_the_uid_literal() {
        let s = schema();
        let hostile = r#"evil" in Nono::Agent::"claude-code"#;
        let mut q = command_query(hostile, "git", &["git"]);
        q.agent = r#"back\slash"#.to_string();
        let (request, entities) = build(&q, &s).unwrap();

        let principal = request.principal().unwrap();
        assert_eq!(principal.type_name().to_string(), "Nono::Caller");
        assert_eq!(
            principal.id().unescaped(),
            hostile,
            "the whole hostile string must remain a single entity id"
        );
        assert!(entities
            .get(&uid("Nono::Agent::\"back\\\\slash\"").unwrap())
            .is_some());
    }
}
