# Tasks: harden-decide-endpoint-surface

TDD throughout: failing test first, RUN it, confirm it fails for the right reason,
then implement. `just test` must pass full **and** filtered (`cargo test --lib server`,
`cargo test --lib audit`, `cargo test --test server`) — see `src/test_log.rs` for the
tracing max-level trap that once made filtered runs lie.

## 1. Pin the upstream header contract before relying on it (#8)

- [x] 1.1 Test in `tests/conformance.rs` (or beside it) asserting the header contract this change depends on: nono's webhook client sends `Content-Type: application/json` and `User-Agent: nono-cli/<version>`. Since the `nono` crate exposes the backend but not an interceptable client, assert against the documented constant/shape available from the dev-dependency, and if the crate genuinely cannot express it, record the verified upstream source location in the test's doc comment and assert what *is* reachable — do not silently skip. A future version bump must break something visible.

## 2. Refuse requests that cannot have come from nono (#8)

- [x] 2.1 Failing test: POST with no `Content-Type` is refused with 415, **no audit line is written**, and a WARN names the observed (absent) content-type
- [x] 2.2 Failing test: each CORS-simple content-type (`text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`) is refused with 415 and writes no audit line
- [x] 2.3 Failing test: `application/json; charset=utf-8` is accepted and decided normally; the type comparison is case-insensitive (`APPLICATION/JSON`)
- [x] 2.4 Failing test: a request carrying `Origin` is refused with 403 **even with a correct content-type**, and writes no audit line
- [x] 2.5 Failing test: a well-formed nono-shaped request (JSON content-type, no `Origin`) is decided exactly as before — assert an existing allow and an existing deny still behave identically
- [x] 2.6 Failing test: a request that passes the header checks but has a malformed body still gets the existing `200` + deny reason + audit line (the fail-closed contract is untouched)
- [x] 2.7 Implement the header gate in `src/server.rs` ahead of body reading; comment states why 4xx is correct here and not a violation of "deny and broken are different signals" (D3)

## 3. Record the observed User-Agent as evidence (#8)

- [x] 3.1 Failing test: a decided line records `user_agent` verbatim; a request with no `User-Agent` records an explicit `null`
- [x] 3.2 Failing test: DEL/C1 control bytes in `User-Agent` are escaped on the raw bytes of the audit file (same standard as the other request-derived fields)
- [x] 3.3 Failing test: a rejected (malformed/unsupported) line carries the key too, with the observed value or `null`
- [x] 3.4 Implement: `AuditRecord.user_agent`, threaded from the request through both record paths; doc comment says **evidence, not verification**, naming both halves (browser JS cannot set it; a local process can)

## 4. stdout becomes telemetry (#9)

- [x] 4.1 Failing test: at the default level, the captured log for a decided command request contains the identifiers and outcome and does **not** contain the attempted command line or its arguments
- [x] 4.2 Failing test: at DEBUG, the resource summary is emitted, control-escaped, and carries `request_id` so it can be joined to the INFO line
- [x] 4.3 Failing test: the audit line still carries the full resource summary at the default level — relocating the detail must not reduce the record
- [x] 4.4 Implement the split as two events (D6): INFO with identifiers, separate DEBUG with `request_id` + resource

## 5. Documentation

- [x] 5.1 README: the header requirement (and the one-flag fix for anyone POSTing by hand); that raising to DEBUG puts attempted command lines into an unprotected stream; and the residual stated plainly — **none of this authenticates nono**, a local process as the same user can still forge records, and closing that needs an upstream bearer token or unix socket
- [x] 5.2 `src/server.rs` module docs: the CORS-simple mechanism (D1) and why `Origin` is checked independently (D2), so a later reader does not "simplify" either away
- [x] 5.3 Confirm no wording anywhere implies the daemon identifies its caller

## 6. Verification

- [x] 6.1 `just test` full and filtered green; `just lint` clean
- [x] 6.2 **`just smoke` against real nono must pass** — this is the load-bearing check for this change, since a wrong content-type comparison would refuse every real request while every unit test passed
- [x] 6.3 Manual probe recorded in the task notes: `curl` without the header (expect 415), with `Origin` (expect 403), with correct header (expect a decision), and confirm the audit log gained **no** line for the two refusals

  Run against a real daemon (`serve` on `127.0.0.1:8199`, shipped policy pack, temp
  audit log), observed:

  | probe | status | body | audit lines added |
  |---|---|---|---|
  | no `Content-Type` | `415` | `{"error":"this endpoint requires Content-Type: application/json"}` | 0 |
  | `Origin: https://evil.example` + `Content-Type: application/json` | `403` | `{"error":"this endpoint refuses requests carrying an Origin header"}` | 0 |
  | `Content-Type: text/plain` | `415` | as the 415 above | 0 |
  | `Content-Type: application/json`, `User-Agent: nono-cli/0.69.0` | `200` | `{"decision":"allow"}` | 1, `"user_agent":"nono-cli/0.69.0"` |
  | `Content-Type: application/json; charset=utf-8` | `200` | `{"decision":"deny","reason":"denied by 10-git:no-history-rewrites"}` | 1, `"user_agent":"curl/8.7.1"` |

  The audit log held **0 lines after the two refusals** and 2 after the two decisions.
  Both refusals logged at WARN naming the observed values
  (`content_type=-`, `content_type=text/plain`, `origin=https://evil.example`,
  `user_agent=curl/8.7.1`), and every INFO decision line carried identifiers and
  outcome with no command line in it. Daemon killed afterwards; nothing left behind
  in the tree.
- [x] 6.4 `openspec validate --changes harden-decide-endpoint-surface` passes

## 7. Remediation round (2026-07-26, re-audit of the #9 half)

The re-audit proved the INFO/DEBUG split stopped at the decision line. Section 4 swept
`server::approve` and left the *other* default-level event about a request:
`Engine::evaluate`'s ambiguity refusal logged `reason = %decision.reason` at WARN, and
that reason quotes the request target verbatim — query string included, which for a
credential proxy is the sensitive half. No test covered the endpoint variant at the
default level (4.1 uses a command request), and README overstated the protection.

- [x] 7.1 Failing test (engine unit, default-level capture): the ambiguity refusal names the cause and `request_id` and contains no part of the path, while the returned deny reason still carries the whole target. Observed before the fix: `the request target must not reach stdout at the default level … WARN … reason=ambiguous endpoint path "/repos/../user/keys?token=leaked-at-default-level" …`
- [x] 7.2 Failing test (HTTP, default level) for the **endpoint** variant of 4.1: a decided endpoint request logs identifiers and outcome and neither the target nor its query string; and an ambiguous one logs the WARN with no path while body + audit line keep the whole target. The refusal case failed as above; the decided case passed on arrival, so it is a regression pin rather than a fix
- [x] 7.3 Test (HTTP, DEBUG): the refused target is still recoverable and joinable by `request_id` — otherwise 7.1/7.2 would be satisfied by deleting the detail, the opposite of D6
- [x] 7.4 Implement: the WARN carries `request_id` + the ambiguity cause, control-escaped; the path stays in the deny reason, the audit line, and the DEBUG detail event
- [x] 7.5 Spec + design: the delta spec says "only at DEBUG" binds every default-level event and pins the refusal's shape; D6 records that the split is a sweep, with the rule of thumb for anything added later (identifiers and causes at the default level, never the resource)
- [x] 7.6 README: the default level carries no resource summary at all — including the ambiguity WARN — and the DEBUG event names the query string explicitly as part of what it exposes
- [x] 7.7 Full + filtered tests green, `just lint` clean, `openspec validate` passes
- [x] 7.8 Live re-probe of the finding's own scenario, scratch policy dir + scratch audit log on `127.0.0.1:8291`, real endpoint envelope with `path=/repos/../user/keys?secret=leaked-at-default-level`:

  | level | daemon stdout | occurrences of the secret on stdout |
  |---|---|---|
  | default (no `RUST_LOG`) | `WARN … request_id=probe-endpoint ambiguity=a ".." path segment appears in the path as sent…` + the clean INFO decision line | **0** |
  | `RUST_LOG=debug` | the same WARN + `DEBUG … decision detail request_id=probe-debug resource=GET https://api.github.com/repos/../user/keys?secret=only-at-debug` | 1, opted in |

  `status=200`, `audit_before=0 audit_after=1`, and the audit line still carries
  `"resource":"GET https://api.github.com/repos/../user/keys?secret=leaked-at-default-level"`
  plus the same path in `reason` — relocated, not lost. A decided (unambiguous)
  endpoint request with `?token=…` likewise put 0 occurrences on stdout and 1 in the
  audit log. Daemons killed afterwards; everything under the scratch dir, nothing left
  in the tree.
