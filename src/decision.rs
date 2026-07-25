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
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            matched: Vec::new(),
            reason: reason.into(),
            eval_us: 0,
        }
    }

    /// Convert a Cedar response into a decision.
    ///
    /// Fails closed on evaluation errors: if any policy errored we cannot know
    /// whether a `forbid` was skipped, so an `Allow` is not trustworthy.
    pub fn from_response(response: &Response, eval_us: u128) -> Self {
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
            return Self {
                allow: false,
                matched,
                reason: format!(
                    "cedar evaluation errors, failing closed: {}",
                    errors.join("; ")
                ),
                eval_us,
            };
        }

        match response.decision() {
            cedar_policy::Decision::Allow => Self {
                allow: true,
                reason: format!("permitted by {}", matched.join(", ")),
                matched,
                eval_us,
            },
            cedar_policy::Decision::Deny => {
                let reason = if matched.is_empty() {
                    "no policy permitted this request (default deny)".to_string()
                } else {
                    format!("denied by {}", matched.join(", "))
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
