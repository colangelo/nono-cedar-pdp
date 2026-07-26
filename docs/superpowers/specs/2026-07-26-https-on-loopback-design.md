---
type: design
title: "https on loopback with a locally-trusted certificate"
description: "Closes PDP impersonation: an opt-in TLS listener whose private key a squatter cannot read, a startup self-test through the same verifier nono uses, and the URL rule that keeps the resolver out of the trust decision. Decisions T1-T11, with what TLS does not buy stated as plainly as what it does."
tags: [design, tls, security, fail-closed, nono, impersonation]
timestamp: 2026-07-26
---

# https on loopback with a locally-trusted certificate

**Date:** 2026-07-26 · **Status:** Approved (brainstorm design review)
**Closes:** Gitea #5 · **Under epic:** #1 (policy-set integrity / the PDP's own trust boundary)
**Prior context:** `docs/superpowers/specs/2026-07-25-nono-cedar-pdp-design.md` §2 "Security
note: PDP impersonation" and §10; ADR-001 (dependency weight in a security daemon).

## 1. Goal

nono's webhook is unauthenticated **in both directions**. It sends no credential, and it
cannot verify who answered. The asymmetric half is impersonation of the PDP: any local
process that binds the port first answers `{"decision":"allow"}` to everything, and
nothing anywhere records that it was not us.

Serving https with a certificate the platform verifier trusts converts that silent full
bypass into a transport error, and a transport error is a denial. The bypass becomes an
outage — which for a fail-closed daemon is the correct direction to fail.

## 2. Verified upstream contract (nono v0.69.0)

Read from source at the pinned tag, not from documentation.

| Fact | Where |
|---|---|
| The webhook client builds `ureq` with `RootCerts::PlatformVerifier` — so a certificate in the **system** trust store is what it checks, and `webpki-roots` is not consulted | `crates/nono-cli/src/approval_runtime.rs:136-138` |
| A **transport** failure (TLS handshake included) returns `Err(NonoError::SandboxInit)`, *not* `Ok(Denied)` | `approval_runtime.rs:207-210` |
| An HTTP **non-2xx** returns `Ok(ApprovalDecision::Denied)` — a different path from the above, and the two are easy to conflate | `approval_runtime.rs:225-232` |
| That `Err` reaches `handle_shim_stream`, which writes exit code **126** and blocks the command | `crates/nono-cli/src/tool-sandbox/platform/macos.rs:902-930` |

**T1 — the fail-closed claim is true, but by the error path, not the deny path.** A
squatter without the key produces `Err`, so nono blocks the command with exit 126; it does
*not* produce a recorded `Denied` with our reason string, because we never got to answer.
The distinction matters to anyone reading nono's audit after a squat: they will see a
sandbox error, not a policy denial. Documented rather than changed — it is upstream's
shape, and both outcomes are closed.

### The platform verifier's server-name handling

`ureq`'s `platform-verifier` feature is `rustls-platform-verifier`. Its macOS path
stringifies the rustls `ServerName` and passes it to `SecPolicyCreateSSL`:

```rust
// Convert IP addresses to name strings to ensure match check on leaf certificate.
let server = server_name.to_str();
```
— `rustls-platform-verifier-0.7.0/src/verification/apple.rs:259`

So an IP literal in the URL becomes an IP-literal hostname for Apple's SSL policy, and
matching an `iPAddress` SAN is on the supported path. This is what makes **T5** viable.

## 3. What this closes, and what it does not

Stated first and plainly, because the failure mode of a control like this is that everyone
downstream remembers the headline and forgets the precondition.

**Closed.** A process that cannot read the private key cannot be believed by nono, even if
it wins the race for the port. Against the sandboxed agent this holds **only because the
key sits outside the agent's read grants** — Seatbelt and Landlock are path-based and do
not change uid, so the agent runs as the same user and file permissions do not separate us
from it. This is the identical argument to D13 for the policy directory, and it fails in
the identical way if an operator points a profile's read grants at the key.

**Not closed.** Arbitrary same-uid code that *can* read the key. It mints a valid
handshake and impersonates us perfectly. TLS is not a defence against the user's own
unsandboxed processes and must never be described as one.

**Not closed.** Availability. A squatter that binds first still denies service — the PDP
fails to bind and exits loudly, or nono's handshake fails and every action is blocked.
That is the trade being made deliberately: a fail-closed daemon prefers an outage to a
silent bypass.

**Not closed.** Confidentiality of the approval payload against someone who already holds
the key, and anything at all about *nono's* identity. nono still sends no credential, so
we still cannot verify the client. That direction is the upstream ask (#13), not this
change.

## 4. Decisions

### T2 — TLS is opt-in; a broken `[tls]` is a refusal, never a downgrade

Absent `[tls]`, behaviour is exactly today's plaintext loopback listener. The shipped
defaults have to work without a certificate ceremony, and a daemon nobody can start is a
worse security outcome than one that starts in the posture it documents.

But `[tls]` **present** and anything wrong — unreadable file, unparseable PEM, key that
does not match the certificate — is a refusal to serve. Falling back to HTTP would be the
worst available behaviour: the operator believes they are protected, the URL in the nono
profile still says `https`, and every approval fails closed for a reason nobody diagnoses
— or worse, the profile says `http` and the bypass is wide open behind a config that
claims otherwise.

Plaintext startup emits one WARN naming impersonation, so the posture is always in the
log rather than inferred from the absence of a line.

### T3 — `axum-server` 0.8 with `rustls`/`ring`

The listener runs `axum_server::bind_rustls`. The router is untouched, so every existing
`tests/server.rs` case exercises the same handlers over the new transport.

**Why not hand-roll it.** axum 0.8's `Listener::accept` returns `(Io, Addr)` with **no
`Result`**, so a hand-written TLS listener must both retry internally and keep the
handshake *off* the accept path. Awaiting the handshake inline compiles, passes a
single-client test, and serialises every handshake — one slow or hostile client stalls
every pending approval on a daemon whose whole job is to answer promptly or be treated as
broken. `axum-server` spawns per connection, so this is correct by construction rather
than by our vigilance.

**Why `ring`, not the default.** `tls-rustls-no-provider` + `rustls/ring` rather than
`tls-rustls`, which pulls `aws-lc-rs` and its C/assembly build. Lighter, and it matches
nono's own explicit choice (`crates/nono-proxy/Cargo.toml:53-58` disables `aws_lc_rs` for
the same reason).

**Dependency justification (ADR-001).** ADR-001's weight argument is about pulling
sigstore, x509 and Keychain code into a security daemon for four serde structs. A TLS
server is not that: it is the feature, not incidental machinery, and `rustls` is the
reference Rust implementation already present in nono's own tree. Recorded here so the
next reader does not have to re-derive that the rule was considered rather than skipped.

### T4 — the private key must not be readable by other local users

Group- or world-readable key ⇒ refuse to serve. Same rule OpenSSH applies to a private
key, and the same shape as `isolation.rs`'s existing refusals, which the check reuses
rather than reimplements — including the ownership rule (owner must be the daemon's
effective uid or root) and the ancestor walk, since whoever can write a parent directory
substitutes their own key file.

This is a refusal rather than a warning because, unlike the CWD check, it is not a proxy.
The CWD heuristic is wrong in both directions and epic #1 is explicit that escalating a
proxy breeds an override flag. A readable private key is the defect itself, measured
directly, with no false-positive story.

Scope, stated in the module docs and the README exactly as `isolation.rs` already does for
its other checks: **this defends against other local users only.** It does nothing about
the sandboxed agent, which shares our uid and is stopped by the key's *location* relative
to the profile's read grants, not by its mode.

### T5 — the URL names the literal address that `bind` names, never `localhost`

The certificate is minted for `localhost`, `127.0.0.1` and `::1` together, so the operator
is not boxed in. But the documented URL is the **literal address matching `bind`** —
`https://127.0.0.1:8181/v1/approve` for the default.

Measured on macOS: `localhost` resolves to `::1` **before** `127.0.0.1`. So a daemon bound
to `127.0.0.1:8181` and a squatter bound to `[::1]:8181` can coexist — both start cleanly,
neither logs anything unusual, and every `https://localhost:8181` request reaches the
squatter. TLS still saves the outcome, because the squatter has no key. But a URL whose
listener is chosen by resolver order makes "which process am I talking to" unanswerable
from the configuration, and that is a bad property in the artifact whose entire purpose is
knowing who answered. Pinning the literal address removes the resolver from the trust
decision.

The daemon does not attempt to *enforce* this — it never sees nono's URL. It is a
documentation rule, and **T6** catches the consequence that matters.

### T6 — startup self-test through the same verifier nono uses

**Before binding the real listener**, the daemon stands up a throwaway TLS listener on
`127.0.0.1:0` with the configured certificate, connects to it with a
`rustls-platform-verifier` client, and refuses to serve if verification fails.

The throwaway listener rather than a self-connection to the real one is deliberate. A
self-test that runs *after* binding has a window — however small — in which the daemon is
accepting approvals it has not yet established anyone can trust, and "refuse to serve"
after having already served is not a refusal. Testing before binding closes the window
entirely.

This works because rustls verifies the certificate against the `ServerName` the client is
given, not against the socket it connected through. So the self-test connects to an
ephemeral port while asserting the server name derived from **`bind`**, which is what makes
it a genuine test of "does this certificate cover the address I am about to serve on".

This answers the operator's actual question — *will nono accept this certificate?* — with
the code that decides it, at startup, instead of in a runbook. It is the same crate ureq's
`platform-verifier` feature uses (§2), so it is not a model of nono's verifier; it is
nono's verifier. It also catches conditions no minting procedure can: a certificate that
expired, a CA removed from the trust store since, a `bind` changed to an address the
certificate does not cover.

Cost: one dependency, `rustls-platform-verifier`. Justified on the same terms as T3 — it
is the load-bearing correctness check for this feature, not incidental machinery.

The self-test connects to the **configured bind address**, which is what the daemon can
know. If the operator then points nono at a different name, T5's documentation rule is
what covers them; the self-test cannot.

### T7 — the certificate is minted, not generated

No self-signed certificate generated on first run. An untrusted certificate fails the
platform verifier, so a generate-on-boot path would produce a daemon that starts happily
and denies every approval — the exact failure T2 exists to prevent, arrived at by another
route. The certificate comes from `mkcert` (documented) or an `openssl` recipe (fallback),
and T6 refuses to serve if it is not actually trusted.

**Certificate Transparency is why a user-added anchor is required, not merely convenient.**
Apple's trust evaluation applies CT policy to publicly-rooted chains: a locally-minted
certificate handed to `security verify-cert -r` fails with *"Unable to find at least 2
signed certificate timestamps (SCTs) from approved logs"* before name matching is even
reached. Certificates chaining to a **user-added trust anchor are exempt** from CT — and
from the 398-day validity cap — which is what makes `mkcert -install` work at all and why
a bare self-signed leaf dropped in a keychain is not an equivalent substitute.

### T8 — cert and key live beside the other home-anchored state

Default `~/.config/nono-cedar-pdp/tls/`. Same reasoning as D13: shipped defaults are
home-anchored so the accidental case — state inside a tree the agent can reach — requires
an operator to go out of their way. `just serve-dev` stays repo-relative and keeps warning.

### T9 — `/healthz` says nothing new

No `tls: true` field. A client that completed a handshake already knows; a client that did
not cannot read the response anyway. #7 has just finished removing disclosure from this
surface and the burden is on additions, not omissions.

### T10 — the squat test drives real nono, and skips loudly

The load-bearing verification is not "our client rejects an untrusted certificate" — this
repo has repeatedly had green tests that agreed with each other and disagreed with nono.
It is: bind the port with a keyless self-signed certificate, run a real intercepted command
under `nono run`, assert it is blocked.

That needs the mkcert CA in the system trust store, which needs a human with an admin
password. So the recipe **detects** the CA and skips with a loud, specific message when it
is absent. A skip that reads like a pass is how a verification step stops being one.

### T11 — the TLS-layer test is a complement, not a substitute

A headless test that stands up our listener and connects with a rustls client configured
like nono's proves the wiring — certificate loads, handshake succeeds, an untrusted
certificate is rejected — without a trusted CA. It runs everywhere and in CI. It is
explicitly *not* the proof that nono denies a squatter; T10 is. Both exist because they
answer different questions, and the cheap one must not be mistaken for the expensive one.

## 5. Config surface

```toml
[tls]                                            # absent ⇒ plaintext, exactly as today
cert = "~/.config/nono-cedar-pdp/tls/cert.pem"   # leaf, plus any intermediates
key  = "~/.config/nono-cedar-pdp/tls/key.pem"
```

Strict as everything else in `Config` — an unknown key inside `[tls]` is a load error, and
`cert`/`key` go through the same `de_path` tilde expansion as `policy_dir` and `audit_log`.
Both keys are required when the table is present: a `[tls]` with only one of them is a
half-configured transport, which T2 says must not start.

Paths are resolved once at startup alongside the other state paths (D7), so the chain the
mode check walks is the chain the listener reads.

## 6. Error matrix

| Condition | Outcome | Why |
|---|---|---|
| No `[tls]` | Serve plaintext, WARN naming impersonation | T2 |
| `[tls]` with one key missing | Refuse to start | T2 — half-configured transport |
| Cert or key unreadable / unparseable / mismatched | Refuse to start | T2 — never downgrade |
| Key group/world-readable, or owned by another user, or under a loose ancestor | Refuse to start | T4 |
| Cert not trusted by the platform verifier for `bind` | Refuse to start | T6 |
| Squatter holds the port when we start | We fail to bind, exit loudly | Pre-existing; unchanged |
| Squatter holds the port and we are not running | nono handshake fails ⇒ `Err` ⇒ exit 126 | T1 |

Every row is a refusal or a block. No row returns allow, and no row silently degrades.

## 7. Verification plan

1. **Empirically confirm the IP SAN accepts** once `mkcert -install` has run. Source says
   it is on the supported path (§2); this is the confirmation. If it fails, T5's fallback
   is `bind = "[::1]:8181"` with `https://localhost:8181` — accepting the resolver in the
   path, and documenting that trade rather than hiding it. Done **first**, because §4's
   URL rule rests on it.
2. Unit: config strictness, the required-pair rule, path resolution.
3. Unit: key-mode and ownership refusals, reusing `isolation.rs`'s existing coverage shape.
4. Integration: no silent HTTP fallback — a daemon configured for TLS must not answer a
   plaintext request.
5. Integration (T11): rustls client configured like nono's completes a handshake; a
   self-signed squatter's certificate is rejected.
6. Integration (T6): a daemon whose certificate is untrusted refuses to start.
7. `just smoke-tls` (T10): real `nono run` denies a keyless squatter. Skips loudly without
   the CA.

## 8. Open items

- Whether the IP SAN verifies in practice — item 1 above. The only fact in this document
  that is argued from source rather than measured, and it is flagged rather than assumed.
- Certificate rotation and expiry are out of scope. mkcert leaves are long-lived, T6 turns
  an expired certificate into a refusal at the next restart, and a daemon that reloads
  certificates on the fly is a larger change than the threat justifies today.
- Client authentication — verifying that the caller really is nono — is unreachable from
  here and stays the upstream ask (#13).
