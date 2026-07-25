# nono-cedar-pdp — v1 Design

**Date:** 2026-07-25 · **Status:** Approved (design review passed; second review pass folded in)
**Prior context:** `docs/research/00-groundwork.md`, `docs/research/01-landscape.md`, `docs/adr/ADR-001-rust-and-cedar-crate.md`

## 1. Goal

A standalone, fail-closed Policy Decision Point that answers nono's `WebhookApproval`
callbacks by evaluating Cedar policies. nono (kernel-enforced sandbox) remains the
Policy Enforcement Point; this daemon only decides. No fork of nono is required:
the integration seam is the stock webhook approval backend, verified against
`nolabs-ai/nono` v0.69.0 source.

## 2. Verified upstream contract (nono v0.69.0)

Facts below were read from source, not docs; file references are to the upstream tree.

- **Request:** `POST <url>` with `{"backend": "<name>", "request": {...}}`;
  the inner request is internally tagged: `"capability_type"` ∈
  `capability | network | endpoint | command` (`crates/nono/src/supervisor/types.rs`).
- **Only `command` and `endpoint` ever reach a webhook.** `Network` is never
  constructed in production code; filesystem `capability` elevation is hardwired to
  the terminal backend (`supervised_runtime.rs`). Cedar arbitration of file grants
  is an upstream PR, not a config option.
- **`command` fields:** `request_id, command, args, caller, intercept_rule, reason?,
  child_pid, session_id`. `caller` is `"session"` or the name of the intercepted
  command that chained the launch (chain-of-custody signal).
- **`endpoint` fields:** `request_id, route_id, upstream, method, path, rule_label,
  reason?, child_pid, session_id` — but the proxy hardcodes `session_id: "proxy"`
  and `child_pid: 0`. Endpoint requests carry no session identity.
- **`args` is lossy:** upstream builds it with `filter_map(|a| from_utf8(a).ok())` —
  non-UTF-8 argv entries are silently dropped, so arg positions shift.
  **Positional argument matching is unsound**; policies must test flag presence.
- **Response:** nono first tries upstream's internal `ApprovalDecision` serde shape,
  then falls back to `{"decision": "...", "reason": "..."}` with synonym sets
  (allow/deny/timeout families). Body capped at 64 KiB.
- **Fail-closed:** non-2xx → `Denied` (reason includes the HTTP status);
  unparseable body / unknown decision → hard error (aborts, never allows);
  default timeout 60 s.
- **Transport:** `ureq` with platform TLS verification; **no Unix-socket support**,
  loopback HTTP(S) only. No authentication in either direction.
- **Config surface:** `command_policies.approval_backends.<name>`
  (`type = "terminal" | "webhook" | "chain"`), `approval_defaults`, and per-rule
  routing `{decision = "approve", backend = "<name>", timeout_secs = N}`.
  `chain` composes backends with `mode = "all" | "any"`.

### Security note: PDP impersonation

The webhook is unauthenticated, so any local process that binds the port first can
answer `allow` to everything. Mitigation path: serve **https on loopback with a
locally-trusted certificate** — a squatter without the key fails TLS, which nono
treats as a transport error and denies. v1 ships plain loopback HTTP; the TLS
hardening is the first follow-up (§10). Upstream ask: bearer-token or UDS support
in the webhook backend config.

## 3. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Rust, embedding `cedar-policy` 4.x | ADR-001: reference engine, upstreamability into a native `CedarApproval` backend |
| D2 | `nono` crate as **dev-dependency only** | Runtime dep pulls sigstore/keyring/x509 weight into a security daemon; a conformance test gives the same drift protection |
| D3 | Entity model A: `Caller in Session in Agent` | Preserves chain-of-custody structurally; supports both `principal == Caller::"session"` and `principal in Agent::"claude-code"` |
| D4 | v1 = both variants (`command` + `endpoint`), decide endpoint, JSONL audit log, policy hot-reload | Endpoint mapping is ~30 lines; rollout safety comes from nono's `chain mode="any"` + terminal fallback, so no dry-run mode is built |
| D5 | Respond with the friendly `{decision, reason}` shape | The enum shape is upstream's internal serde representation and will drift; the friendly shape is the stable public contract |
| D6 | `args` modeled as `Set<String>` | Cedar sets have no index access → positional matching is *unexpressible*, enforcing the lossy-argv finding structurally |
| D7 | Keep last-good policy set on failed hot-reload | A bad edit mid-session must not deny-all a running agent; failed reload logs loudly. Startup with invalid policies still refuses to run |
| D8 | Loopback HTTP on `127.0.0.1:8181`, no portless name | Fewer hops and no squattable hostname in a security path |

## 4. Architecture

One Rust binary (lib + bin). The lib half (`wire`, `query`, `cedar/`) is what a
future native-backend PR into nono would carry over; the adapter/HTTP half is
disposable.

```
src/
  main.rs                   CLI: serve | check <fixture.json> | validate
  wire.rs                   mirror serde types for ApprovalRequest / responses
  query.rs                  PolicyQuery — adapter-neutral internal boundary
  adapter/nono_webhook.rs   envelope -> PolicyQuery -> response body
  cedar/schema.rs           embedded nono.cedarschema, compiled at startup
  cedar/entities.rs         PolicyQuery -> Cedar Request + per-request entity slice
  cedar/engine.rs           PolicySet load, validate, ArcSwap hot-reload, authorize
  decision.rs               Decision + reason from Cedar diagnostics
  audit.rs                  JSONL decision log
  config.rs                 bind addr, policy dir, agent map, tls (later)
```

Dependencies: `cedar-policy` 4.11.x, `axum`/`hyper` + `tower-http` (CatchPanicLayer),
`serde`/`serde_json`, `arc-swap`, `notify`, `clap`, `tracing`.
Dev-dependencies: `nono` (pinned, for the conformance test).

## 5. Cedar schema

The load-bearing artifact. Embedded in the binary; policies are validated against it
at load and at hot-reload.

```cedar
namespace Nono {
  entity Agent;
  entity Session in [Agent];
  entity Caller  in [Session];

  entity Command {
    command:   String,       // "git"
    args:      Set<String>,  // exact-membership tests only (D6)
    argv:      String,       // space-joined; forbid-only substring checks (see caveat)
    arg_count: Long,         // count of post-filter args (lossy-argv caveat)
  }

  entity HttpEndpoint {
    route_id: String,
    upstream: String,
    method:   String,
    path:     String,
  }

  action launchCommand appliesTo {
    principal: [Caller],
    resource:  [Command],
    context: {
      backend:        String,   // envelope backend name
      intercept_rule: String,
      caller_kind:    String,   // DERIVED by the adapter: "session" | "command"
      reason?:        String,   // omitted when upstream sends null
      child_pid:      Long,
      session_id:     String,
    }
  };

  action httpRequest appliesTo {
    principal: [Caller],
    resource:  [HttpEndpoint],
    context: {
      backend:    String,
      rule_label: String,
      reason?:    String,
    }
  };
}
```

Schema caveats (documented here and in the starter policy pack):

- **`argv` is forbid-only.** Cedar strings support only `like` globs; a substring
  pattern (`argv like "*--force*"`) also matches when the text appears *inside a
  single argument* (`-m "do not --force"`). Over-matching is fail-safe in a
  `forbid` (spurious deny → terminal fallback prompts) but unsound in a `permit`.
  Exact flag tests use `resource.args.contains("--force")`.
- **`caller_kind` is derived** in the adapter (`caller == "session"`), not a wire
  field — the conformance test must not expect it from nono.
- **`arg_count`** counts args *after* upstream's lossy UTF-8 filter.
- **Entity ids stay short** (`Caller::"session"`, `Caller::"git"`, `Caller::"proxy"`)
  because the entity slice is per-request; session identity lives in the parent
  `Session` entity and in context.

### Entity construction per request

| Request | Principal slice | Resource |
|---|---|---|
| `command` | `Caller::"<caller>" in Session::"<session_id>" in Agent::"<mapped>"` | `Command::"<request_id>"` with attrs |
| `endpoint` | `Caller::"proxy" in Session::"proxy" in Agent::"<mapped>"` | `HttpEndpoint::"<request_id>"` with attrs |

`Agent` is resolved from config keyed on the **envelope backend name**
(`[agents] cedar = "claude-code"`); unmapped names → `Agent::"unknown"`.
**Granularity note:** two different agents routed through one backend name are
indistinguishable. The supported pattern is two named webhook backends in the nono
profile pointing at the *same URL* — the envelope's `backend` field then
distinguishes them, and each maps to its own `Agent`. Zero PDP code.

## 6. Data flow

```
nono ──POST /v1/approve──▶ adapter (wire.rs deserialize, strict)
                             │ PolicyQuery
                             ▼
                           cedar/entities (slice + Request)
                             │
                             ▼
                           Authorizer::is_authorized( ArcSwap<PolicySet> )
                             │
                             ├─▶ audit.rs: one JSONL line
                             ▼
                           {"decision":"allow"} | {"decision":"deny","reason":"<policy ids>"}
```

Audit line fields: timestamp, request_id, session_id, backend, principal, action,
resource summary, decision, matched policy ids, eval time (µs).

## 7. Error handling — deny vs unhealthy are different signals

| Situation | Response | Why |
|---|---|---|
| Malformed JSON / unknown `capability_type` | `200` deny + reason | our reason lands in nono's audit trail; 4xx would deny with a useless generic reason |
| `capability` / `network` variant | `200` deny, "unsupported variant" | fail closed on anything upstream adds later |
| Policy set invalid at startup | refuse to start | fail fast, not fail quiet |
| Policy set invalid on hot-reload | keep last-good, log error | D7 |
| Cedar evaluation error | `200` deny + error log | schema validation should make this unreachable |
| No policy set loaded / unhealthy | `503` | nono's denial reason then names HTTP 503 — unambiguously "PDP broken", not "policy said no" |
| Handler panic | tower `CatchPanicLayer` → `5xx` | a dropped connection would surface as an opaque transport error |

Empty policy set denies everything (Cedar default-deny) — correct, logged loudly at
startup. Hot-reload parses + validates into a staging `PolicySet` and swaps the
`ArcSwap` only on success. `GET /healthz` reports policy-set generation + load time
for launchd/monitoring.

## 8. Deployment & rollout

No dry-run code in the PDP; stage through nono's own config:

```toml
[approval_backends.cedar]          # endgame: Cedar alone
type = "webhook"
url = "http://127.0.0.1:8181/v1/approve"
timeout_secs = 5

[approval_backends.cedar-or-ask]   # start here: Cedar denies -> terminal prompts
type = "chain"
mode = "any"
backends = ["cedar", "terminal"]

[approval_backends.cedar-and-ask]  # paranoid: Cedar AND a human must allow
type = "chain"
mode = "all"
backends = ["cedar", "terminal"]
```

Run: `just serve` foreground; launchd plist for always-on (follow-up).

## 9. Testing

1. **Conformance test (anti-drift):** construct `nono::ApprovalRequest` values with
   the real upstream crate (dev-dep), serialize with upstream serde, assert
   `wire.rs` round-trips. Bumping the pinned `nono` version turns wire drift into a
   CI failure instead of a silent misparse.
2. **Decision matrix:** table-driven policy-set × request → expected decision,
   both actions.
3. **Fail-closed suite:** one test per row of the §7 table.
4. **Lossy-argv test:** non-UTF-8 argv entry → documents the dropped arg; proves
   positional policies are unexpressible against the schema.
5. **End-to-end smoke:** nono profile with an intercept `approve` rule routed to the
   PDP; run a harmless intercepted command on this Mac; assert the decision came
   from Cedar and appears in both nono's audit and our JSONL.

## 10. Follow-ups (explicitly out of v1)

- **https-on-loopback** with locally-trusted cert (PDP impersonation fix, §2).
- **Upstream engagement:** comment on nono #879 (what does "completed" mean; offer
  this repo as the reference adapter); file the lossy-argv `filter_map` issue;
  ask for webhook auth (bearer/UDS).
- **PORC compatibility adapter** (ToolHive `httpv1`) — second `adapter/` module.
- **Native `CedarApproval` upstream PR** — lifts `wire`/`query`/`cedar` wholesale.
- Signed decision receipts (ScopeBlind-style) if the audit requirement hardens.
- launchd always-on service.
