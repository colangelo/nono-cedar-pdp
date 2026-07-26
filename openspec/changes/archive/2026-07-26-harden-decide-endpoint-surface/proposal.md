# Proposal: harden-decide-endpoint-surface

## Why

Two backlog issues on the surface *around* the decision rather than the decision
itself — what the daemon accepts, and what it discloses. Both are the first things
a reviewer looks at, and both are currently weaker than the decision path they sit
next to.

**#8 — `/v1/approve` accepts unauthenticated audit-record injection.** There is no
authentication, `Host`/`Origin` validation or content-type check on the decide
endpoint, so any local process — and, importantly, **a web page you merely visit**,
via a CORS-simple cross-origin POST — can submit an envelope with attacker-chosen
`backend`, `session_id` and argv and have it written to the audit log as though nono
had asked. This cannot produce a wrong *allow* for a real command: nono only honours
the response to its own request. The damage is to the trail — and the trail is the
compensating control for an unauthenticated webhook, so one an attacker can write to
is worth less than one they cannot.

**#9 — the INFO decision line copies full command lines to stdout.** Every decision
logs the full resource summary — the command line an agent attempted, or the API path
it requested — to whatever stream the operator redirected. The audit log got careful
treatment (owner-only `0600`, control-byte escaping, non-fatal write failures);
stdout got escaping and nothing else, despite carrying the same content. stdout may
land in a shared journal, a log aggregator, or terminal scrollback, none of which
inherit `0600`.

**What is verified, and what is therefore not on the table.** Read from nono 0.69.0
(`crates/nono-cli/src/approval_runtime.rs`), the webhook POST sends exactly two
headers — `Content-Type: application/json` and `User-Agent: nono-cli/<version>` —
and the webhook config has no field for a token or custom headers. So a shared
secret is **impossible today**, not merely unimplemented; that stays an upstream ask
(backlog #13, bearer token or UDS). This change takes what is achievable without an
upstream change and does not pretend to more.

## What Changes

- **Reject requests that cannot have come from nono.**
  - Require `Content-Type: application/json`. This is the load-bearing control: a
    CORS-*simple* cross-origin POST may only use `text/plain`,
    `application/x-www-form-urlencoded` or `multipart/form-data`, so demanding JSON
    forces a preflight, and the service sends no CORS headers, so the preflight
    fails and the POST never reaches the handler. **This closes the only vector that
    does not already require local code execution.**
  - Reject any request carrying an `Origin` header. nono never sends one; a browser
    always does. Independent of the content-type check, on purpose.
- **Record the observed `User-Agent` in the audit line** as *evidence*, not
  verification. A real request carries `nono-cli/<version>`; browser JavaScript
  cannot set the header at all, and a local forger has to bother. An investigator
  gets to see what was actually presented.
- **stdout becomes operational telemetry.** The INFO decision line carries the
  identifiers and the outcome (`request_id`, `session_id`, `backend`, action, allow,
  matched policy ids, timing). The resource summary — the attempted command line or
  API path — moves to DEBUG, so the detail is available deliberately during
  development but is not sprayed into a stream with no permissions by default. The
  audit log is unchanged: it remains the complete record.
- **Document the residual honestly**, in the same words everywhere: none of this
  authenticates nono. A local process running as the same user can still forge audit
  records, and that is inherent while the webhook carries no credential.

Deliberately **not** included, with reasons:

- **No rate limit.** nono treats any non-2xx as `Denied`, so a limit converts an
  audit-pollution vector into a way to deny an agent's legitimate work. An attacker
  able to saturate a generous limit can already run local code.
- **No peer-credential check.** macOS exposes no peer uid/pid for TCP loopback
  (`LOCAL_PEERCRED` is a unix-socket facility), so this needs the UDS that is part of
  the same upstream ask.
- **No `child_pid` ancestry verification.** Fragile by construction: pid reuse, the
  child may have exited by the time we look, and endpoint requests send `child_pid`
  0.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `approval-webhook`: gains a requirement that requests which cannot have come from
  nono are refused before evaluation — content-type required, `Origin` rejected —
  while keeping the fail-closed rule that a *decision-shaped* refusal is still a
  `200` deny that nono can record.
- `decision-audit-log`: audit lines gain the observed `User-Agent`, recorded as
  evidence with the honest caveat that it is forgeable by a local process.
- `pdp-operations`: gains a requirement separating operational telemetry from the
  decision record — the decision detail belongs in the audit log, not in stdout by
  default.

## Impact

- `src/server.rs`: header checks before body handling; the INFO/DEBUG split.
- `src/audit.rs`: `AuditRecord` gains `user_agent`; both record paths populate it.
- `src/adapter/nono_webhook.rs`: `RejectedContext` may need to carry the observed
  agent for the rejected path.
- `README.md`: the residual, stated plainly; a note that DEBUG-level output inherits
  the audit log's sensitivity without its permissions.
- Audit-line consumers: one new key, additive; the key set stays fixed per line kind.
- Gitea: closes #8 and #9. Backlog #13 (upstream auth ask) remains open and is now
  the *only* route to actually authenticating nono.
