//! Visibility tripwire for the D15 ambiguous-path guard's bypass pieces.
//!
//! `Engine::evaluate` denies an ambiguous endpoint path **before any policy is
//! consulted**. The crate used to export the two pieces that together authorize a
//! request without passing that guard: `cedar::entities::build` (policy query →
//! Cedar request + entities) and `Decision::from_response` (raw authorizer
//! response → decision). Both are `pub(crate)` now — the same closed-seam
//! property `Engine::from_loaded_unchecked` already has — so the only externally
//! reachable route from a policy query to a decision runs the ambiguity check.
//! The bin crate (`src/main.rs`) and every integration test are the compile-time
//! canary that the *intended* public API still suffices.
//!
//! Textual on purpose, same posture as `tests/docs.rs`: a compile-fail harness
//! (`trybuild`) is a heavy dev-dependency for two declarations. The assertions
//! fail when the expected marker is ABSENT, so moving or renaming the items
//! breaks this loudly — a false alarm to update consciously, never a false pass.
#![allow(clippy::unwrap_used, clippy::panic)]

fn source(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{rel} is gone or moved ({e}). The D15 guard's bypass pieces must not be \
             exported; this tripwire pins their visibility in that file, so re-point \
             it at the new home of cedar::entities / Decision::from_response"
        )
    })
}

#[test]
fn the_d15_guards_bypass_pieces_are_not_exported() {
    let cedar_mod = source("src/cedar/mod.rs");
    assert!(
        cedar_mod.contains("pub(crate) mod entities;"),
        "src/cedar/mod.rs no longer declares `pub(crate) mod entities;`. The D15 \
         guard's bypass pieces must not be exported: `cedar::entities::build` turns \
         a policy query into a Cedar request/entities pair without the \
         ambiguous-endpoint-path check, so a public export lets an external caller \
         authorize around the guard `Engine::evaluate` runs first"
    );

    // The module marker alone is not enough: a `pub fn` inside a `pub(crate)`
    // module can still leak through a one-line `pub use self::entities::build;`
    // without disturbing the module declaration above. Capping the function
    // itself at `pub(crate)` turns any such re-export into a hard compile error
    // (E0364, "only public within the crate, and cannot be re-exported
    // outside") — the same cap that already protects `Decision::from_response`.
    let entities = source("src/cedar/entities.rs");
    assert!(
        entities.contains("pub(crate) fn build"),
        "src/cedar/entities.rs no longer declares `pub(crate) fn build`. The D15 \
         guard's bypass pieces must not be exported: a `pub fn build` inside the \
         pub(crate) module can be re-exported with a one-line `pub use` that \
         leaves the module marker intact, so the function itself must carry the \
         pub(crate) cap that makes any re-export a compile error (E0364)"
    );

    let decision = source("src/decision.rs");
    assert!(
        decision.contains("pub(crate) fn from_response"),
        "src/decision.rs no longer declares `pub(crate) fn from_response`. The D15 \
         guard's bypass pieces must not be exported: a public raw-`Response` \
         conversion is the other half of authorizing a request without \
         `Engine::evaluate`, whose guard denies ambiguous endpoint paths before \
         any policy is consulted"
    );
}
