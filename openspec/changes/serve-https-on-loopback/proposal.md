# Proposal: serve-https-on-loopback

## Why

Gitea #5, under epic #1. nono's webhook is unauthenticated **in both directions**: it sends
no credential, and it cannot verify who answered. The asymmetric half is impersonation of
the PDP — any local process that binds the port first answers `{"decision":"allow"}` to
everything, and nothing anywhere records that it was not us. Design §2's "Security note:
PDP impersonation" named this in v1 and deferred it to §10; this is that follow-up.

The fix is available because nono's webhook client uses the **platform** TLS verifier
(`approval_runtime.rs:136-138`, `RootCerts::PlatformVerifier`). A certificate in the system
trust store means a squatter without the private key cannot complete a handshake, and a
failed handshake blocks the command. The silent full bypass becomes an outage, which for a
fail-closed daemon is the correct direction to fail.

## What Changes

- **An opt-in `[tls]` config table** (`cert`, `key`). Absent ⇒ today's plaintext listener,
  unchanged. Present ⇒ https, and **any** problem with the pair is a refusal to serve.
- **Never a silent downgrade.** A daemon that falls back to HTTP when TLS is misconfigured
  is worse than one that never had TLS: the operator believes they are protected while the
  profile's `https` URL fails closed for an undiagnosable reason — or the profile says
  `http` and the bypass is wide open behind a config that claims otherwise.
- **Plaintext startup emits a WARN naming impersonation**, so the posture is in the log
  rather than inferred from a missing line.
- **The private key must not be readable by other local users** — group/world-readable,
  foreign ownership, or a loose ancestor is a refusal, reusing `isolation.rs` rather than
  reimplementing its walk.
- **A startup self-test through `rustls-platform-verifier`** — the same crate ureq uses —
  refuses to serve when the certificate is not actually trusted for the bind address.
- **A documented minting procedure** (`mkcert`, with an `openssl` fallback) and a `just`
  recipe, plus `just smoke-tls`: a real `nono run` against a keyless squatter.

## The URL must name the literal address, never `localhost`

Stated here because it is the non-obvious half and it is a documentation rule the daemon
cannot enforce.

Measured on macOS: `localhost` resolves to `::1` **before** `127.0.0.1`. A daemon bound to
`127.0.0.1:8181` and a squatter bound to `[::1]:8181` therefore coexist — both start
cleanly, neither logs anything unusual, and every `https://localhost:8181` request reaches
the squatter. TLS still saves the outcome, because the squatter has no key. But a URL whose
listener is chosen by resolver order makes "which process am I talking to" unanswerable
from the configuration, which is a bad property in the one artifact whose entire purpose is
knowing who answered.

So the certificate is minted for `localhost`, `127.0.0.1` and `::1` together, and the
**documented URL is the literal address matching `bind`**.

## What this does not buy

Recorded in the proposal, not just the design, because the failure mode of a control like
this is that everyone downstream remembers the headline and forgets the precondition.

- **Against the sandboxed agent it holds only because the key sits outside the agent's read
  grants.** Seatbelt and Landlock are path-based and do not change uid; the agent runs as
  the same user, so file permissions do not separate us from it. Identical to D13's argument
  for the policy directory, and it fails identically if a profile's read grants are pointed
  at the key.
- **Nothing against same-uid code that can read the key.** It mints a valid handshake and
  impersonates us perfectly.
- **Nothing about nono's identity.** nono still sends no credential, so we still cannot
  verify the client. That direction stays the upstream ask (#13).
- **Availability is deliberately traded away.** A squatter that binds first still denies
  service. A fail-closed daemon prefers an outage to a silent bypass.

## A transport failure is not a recorded denial

nono maps a TLS failure to `Err(NonoError::SandboxInit)` (`approval_runtime.rs:207-210`),
which `handle_shim_stream` turns into exit code 126 — **not** to `Ok(Denied)`, which is what
an HTTP non-2xx produces (`approval_runtime.rs:225-232`). Both are closed, but an
investigator reading nono's audit after a squat sees a sandbox error, not a policy denial
with our reason string. Documented rather than changed: it is upstream's shape.

## Capabilities

### Added Capabilities

- `pdp-operations`: "Serve https on loopback with a locally-trusted certificate" — the
  listener, the refusals, the key protection, the self-test, and the URL rule.

### Modified Capabilities

- `pdp-operations`: "Strict operator configuration" gains the optional `[tls]` table and
  the rule that its two keys are required together.

## Impact

- `Cargo.toml`: `axum-server` (`tls-rustls-no-provider` + `rustls/ring`, matching nono's own
  explicit rejection of `aws-lc-rs`) and `rustls-platform-verifier`. Both justified against
  ADR-001 in the design — a TLS server is the feature, not incidental machinery.
- `src/config.rs`: the `[tls]` table, strict, tilde-expanded, both-or-neither.
- `src/isolation.rs`: the key-readability refusal, reusing the existing ancestor walk.
- `src/server.rs`: a TLS arm in `serve`; the router is untouched, so every existing
  `tests/server.rs` case exercises the same handlers over the new transport.
- `src/main.rs`: path resolution for the new pair, the self-test, the plaintext WARN.
- `Justfile`: `mint-cert`, `smoke-tls`.
- `README.md`, design §10 pointer, `docs/audits/` if the residual list moves.
- Gitea: closes #5.
