//! Decision type and reason construction.

use crate::wire::WebhookResponse;
use cedar_policy::Response;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allow: bool,
    /// Cedar policy ids that determined the outcome. Empty on a default deny.
    pub matched: Vec<String>,
    pub reason: String,
    pub eval_us: u128,
}

impl Decision {
    /// Reasons are sanitized on the way in: they carry request-derived text (a
    /// command name, a Cedar error quoting an attribute) into nono's audit trail
    /// and our own logs, so control characters must never survive.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            matched: Vec::new(),
            reason: crate::sanitize::control_escape(&reason.into()),
            eval_us: 0,
        }
    }

    /// Convert a Cedar response into a decision.
    ///
    /// Fails closed on evaluation errors: if any policy errored we cannot know
    /// whether a `forbid` was skipped, so an `Allow` is not trustworthy.
    ///
    /// Crate-private on purpose: a public raw-`Response` conversion is one half
    /// of authorizing a request without `Engine::evaluate`, whose D15 guard
    /// denies ambiguous endpoint paths before any policy is consulted. Pinned by
    /// `tests/public_api.rs`.
    pub(crate) fn from_response(response: &Response, eval_us: u128) -> Self {
        let mut matched: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();
        matched.sort();

        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        if !errors.is_empty() {
            // Cedar error text can quote request-supplied values.
            return Self {
                allow: false,
                matched,
                reason: crate::sanitize::control_escape(&format!(
                    "cedar evaluation errors, failing closed: {}",
                    errors.join("; ")
                )),
                eval_us,
            };
        }

        match response.decision() {
            cedar_policy::Decision::Allow => Self {
                allow: true,
                reason: crate::sanitize::control_escape(&format!(
                    "permitted by {}",
                    matched.join(", ")
                )),
                matched,
                eval_us,
            },
            cedar_policy::Decision::Deny => {
                let reason = if matched.is_empty() {
                    "no policy permitted this request (default deny)".to_string()
                } else {
                    crate::sanitize::control_escape(&format!("denied by {}", matched.join(", ")))
                };
                Self {
                    allow: false,
                    matched,
                    reason,
                    eval_us,
                }
            }
        }
    }

    pub fn to_wire(&self) -> WebhookResponse {
        if self.allow {
            WebhookResponse::Allow
        } else {
            WebhookResponse::Deny {
                reason: self.reason.clone(),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn deny_carries_no_matched_policies() {
        let d = Decision::deny("nope");
        assert!(!d.allow);
        assert!(d.matched.is_empty());
        assert_eq!(d.reason, "nope");
        assert_eq!(
            d.to_wire(),
            WebhookResponse::Deny {
                reason: "nope".to_string()
            }
        );
    }

    /// The deny reason is echoed to nono and written to the audit log, so bytes
    /// an attacker chose (a command named with an ANSI erase-line sequence) must
    /// not travel in it verbatim.
    #[test]
    fn deny_reasons_carry_no_raw_control_bytes() {
        let d = Decision::deny("could not build request: git\u{1b}[2K\rDENY OVERRIDDEN");
        assert!(!d.reason.chars().any(char::is_control), "{:?}", d.reason);
        assert!(d.reason.contains("\\u{001b}"), "{}", d.reason);
        assert_eq!(
            d.to_wire(),
            WebhookResponse::Deny {
                reason: d.reason.clone()
            },
            "the sanitized reason is what reaches nono"
        );
    }

    #[test]
    fn allow_maps_to_the_allow_wire_shape() {
        let d = Decision {
            allow: true,
            matched: vec!["a:b".to_string()],
            reason: "permitted by a:b".to_string(),
            eval_us: 1,
        };
        assert_eq!(d.to_wire(), WebhookResponse::Allow);
    }
}
