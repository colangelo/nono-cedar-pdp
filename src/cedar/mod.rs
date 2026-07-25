pub mod engine;
// Crate-private on purpose: `entities::build` turns a policy query into a Cedar
// request without the ambiguous-endpoint-path guard `Engine::evaluate` runs
// first, so exporting it would let a caller authorize around that guard (D15).
// Pinned by `tests/public_api.rs`.
pub(crate) mod entities;
pub mod schema;
