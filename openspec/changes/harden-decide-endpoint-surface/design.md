# Design: harden-decide-endpoint-surface

## Context

`src/server.rs::approve` reads the body and evaluates. It inspects no headers, so it
cannot tell nono's client from any other local POST — nor from a cross-origin POST
issued by a page the operator merely visited. Separately, the INFO decision line
carries `resource = %query.resource_summary()`, i.e. the attempted command line, to
an unprotected stream.

Ground truth read from nono 0.69.0 `crates/nono-cli/src/approval_runtime.rs`, so the
design rests on the client's real behaviour rather than on inference:

```rust
.post(&self.url)
.header("Content-Type", "application/json")
.header("User-Agent", &format!("nono-cli/{}", env!("CARGO_PKG_VERSION")))
.send(body)
```

Two headers, no auth, and no config field anywhere for a token or extra headers. A
shared secret is therefore *impossible* today, not merely absent.

## Goals / Non-Goals

**Goals**: close the remote (browser) vector completely; record what the caller
presented as evidence; stop leaking attempted command lines to stdout by default;
state the residual honestly.

**Non-Goals**: authenticating nono (needs upstream — backlog #13); a rate limit
(see D4); peer credentials (needs a unix socket, same upstream ask); changing any
decision outcome. This change must not alter a single allow/deny.

## Decisions

### D1 — Content-Type is the control, not a formality

Requiring `application/json` is what actually stops a drive-by page, and the
mechanism is worth writing down because it is easy to mistake for box-ticking. The
CORS "simple request" exemption — the one that needs no preflight — permits only
`text/plain`, `application/x-www-form-urlencoded` and `multipart/form-data`. To send
`application/json` cross-origin the browser must preflight with `OPTIONS`; we serve
no CORS headers and no `OPTIONS` route, so the preflight fails and the POST is never
issued. **That closes the only vector not already requiring local code execution.**

Media-type parameters are tolerated (`application/json; charset=utf-8`) — the
essence is the type, and a future client may add a charset. Comparison is
case-insensitive on the type, per RFC 9110.

### D2 — Reject `Origin` as an independent second control

nono never sends `Origin`; every browser-issued cross-origin request does. Checking
it is redundant with D1 *today*, and that is the point: if a future nono release
started sending a different content-type, D1 would have to be relaxed and D2 would
still hold. Two independent checks, neither load-bearing alone.

### D3 — These refusals are not decision-shaped

The daemon's existing contract is that a *decision-shaped* failure returns `200`
with a deny reason, because nono records our reason and a non-2xx becomes a bare
`returned HTTP <status>`. That reasoning does not apply here: a request failing the
header checks **was not asked by nono**, so there is no nono waiting on a reason and
nothing is owed to it. Returning 4xx and writing *no* audit line is correct — writing
one would recreate the very injection this closes, just with a `refused` label.

This is the one place the fail-closed rule reads differently, so the spec says it
explicitly: 4xx here is not a violation of "deny and broken are different signals",
it is the third case — "this was not a request".

Status choice: `415 Unsupported Media Type` for the content-type failure (exactly
what it means) and `403 Forbidden` for `Origin`. Both logged at WARN with the
observed values control-escaped, so probing is visible.

### D4 — No rate limit, deliberately

nono maps any non-2xx to `Denied`. A limit therefore converts "an attacker can
pollute the log" into "an attacker can deny the agent's legitimate work", which is a
worse trade for a fail-closed daemon: log pollution is recoverable and visible, a
denial is neither. And an attacker who can saturate a generous ceiling can already
execute local code, at which point they have better options than flooding us.
Recorded here so it reads as a decision rather than an oversight.

### D5 — User-Agent is evidence, not verification

Recorded verbatim (control-escaped) as a new nullable audit key. The honest framing
matters more than the value: browser JS cannot set `User-Agent`, so its absence or
oddity is a real signal; a local forger sets it trivially, so its presence proves
nothing. Both halves get stated wherever the field is described, because a field
that *looks* like authentication is worse than no field at all.

### D6 — INFO/DEBUG split rather than removal

The resource summary moves to a separate DEBUG event rather than being dropped: it
is genuinely the first thing you want when a policy will not match, and deleting it
would push developers to re-add it ad hoc. Keeping the INFO line's identifiers means
an audit line and a log line remain correlatable by `request_id` — which is what
makes relocating the detail costless.

Implementation note: emit one INFO event with the identifiers, and a separate DEBUG
event carrying `request_id` plus the resource, rather than one event whose fields
vary by level (`tracing` fields are fixed per event). The DEBUG event must repeat
`request_id` or it cannot be joined to anything.

The split is a *sweep*, not one edit: the decision line is not the only default-level
event about a request. `Engine::evaluate`'s ambiguity refusal logged the deny reason at
WARN, and that reason quotes the request target verbatim — so cleaning the INFO line
alone left the whole target, query string included, on stdout for any agent willing to
send a `..`. That WARN stays at WARN (a refused path is worth seeing without opting in)
and reports the ambiguity plus `request_id`; the target is recoverable from the DEBUG
detail event and was never absent from the deny reason or the audit line. Rule of
thumb for anything added later: a default-level event may name identifiers and causes,
never the resource.

## Risks / Trade-offs

- **[The Content-Type requirement could break a real nono release]** If a future
  nono stopped sending the header, every decision would be refused — a total outage,
  fail-closed but severe. → `tests/conformance.rs` already pins the wire contract
  against nono's own types; this change adds a test asserting the *header* contract
  in the same spirit, and `just smoke` exercises a real `nono run` end to end. A
  version bump that changes it fails the suite rather than the deployment.
- **[Operators with a non-nono client]** Anyone driving `/v1/approve` by hand (curl
  in a runbook, a test harness) must now send the header. → It is one flag
  (`-H 'Content-Type: application/json'`), it is what any JSON API expects, and the
  WARN line names exactly what was wrong. README gets the note.
- **[Losing detail from stdout could hamper triage]** → It is one env var away, and
  the audit log never lost it.
- **[A new audit key]** Additive; key set stays fixed per line kind. Same posture as
  the `child_pid`/`intercept_rule`/`rule_label` addition.

## Migration Plan

No config change. Operators who POST by hand add a content-type header. Anyone
parsing audit JSONL sees one new key. Rollback is a revert; no state migrates.

## Open Questions

None. The two that were open — how far to go on #8, and what stdout is for — are
settled in D1–D4 and D6.
