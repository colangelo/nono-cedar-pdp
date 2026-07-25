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
  command that chained the launch (chain-of-custody signal). `command` carries the
  command **name**; `args` is the shim process's raw argv, `args[0]` included — and
  `args[0]` is a per-run absolute shim path, *not* the name (see the correction below).
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

### Correction (2026-07-25, post-implementation audit): `args[0]` is a per-run shim path

The payload this design and the implementation plan documented as the "real
command-request JSON" — `"args": ["git", "push"]` — was **copied from upstream's
unit-test fixture** (`crates/nono/src/supervisor/mod.rs:209-217`, inside
`#[cfg(test)] mod tests`). It was produced by upstream's serializer, but from a value
that only ever exists in a test; it never reflected runtime. What nono actually sends
looks like this (the `args[0]` value is verbatim from an audit line of the end-to-end
smoke run; the ids are from that same run, the shape is the point):

```json
{"backend":"cedar","request":{"capability_type":"command",
 "request_id":"tool-sandbox-approve-git-1784990893285791000","command":"git",
 "args":["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git","status"],
 "caller":"session","intercept_rule":"status","reason":null,
 "child_pid":13820,"session_id":"35abc0894927242e"}}
```

Why, read from the v0.69.0 tree:

- `resolve_program` is `which::which(program)`
  (`crates/nono-cli/src/exec_strategy.rs:56`) and the exec builds argv as
  `[resolved_program_path, args…]` (`exec_strategy.rs:537-540`). With the tool-sandbox
  shim directory prepended to `PATH`, the resolved path *is* the shim.
- The shim forwards its own `std::env::args_os()` verbatim as the request's `argv`
  (`tool-sandbox/platform/macos.rs:632`) and derives `command` separately from
  `current_exe().file_name()` (`macos.rs:624`). Hence: `command` = name, `args[0]` =
  whatever path the caller execed.
- The supervisor copies that argv straight into `ApprovalRequest::Command.args`
  (`macos.rs:1168` and `macos.rs:1260`, through the lossy UTF-8 filter). Upstream's own
  field doc says "Full argument list including argv[0]"
  (`crates/nono/src/supervisor/types.rs:107`).
- The shim directory is unique per run:
  `<base>/nono-tool-sandbox-<pid>-<unix nanos>-<hex nonce>/shims/<command>`, base
  `/private/tmp` on macOS (`macos.rs:4649`, `unique_runtime_path` at `macos.rs:4748`)
  and `temp_dir()` on Linux (`linux.rs:2848`, `linux.rs:2865`). **The value changes on
  every run**, so no literal can match it.
- nono itself never treats `argv[0]` as an argument: its own invocation-policy matcher
  is `argv.iter().skip(1)` (`tool-sandbox/policy.rs:243`).

`args[0]` is therefore **whatever the exec caller put in argv[0]**, and it is not under
the policy author's control: nono's own `nono run` path resolves the program with
`which` and so passes the absolute shim path (the observed case), whereas a shell inside
the sandbox running `git status` execs the same shim with `argv[0] = "git"`. So an
anchored pattern is not reliably broken either — it can fire for one launch path and
silently not fire for another, which is worse than a consistent failure. Nothing that
depends on `args[0]` is sound.

Consequences for policy authoring:

- **`resource.command` is unaffected.** It is a separate field carrying the command
  name (`"git"`), and remains the correct thing to match a command on.
- **Unanchored `argv` globs still work.** `resource.argv like "*--force*"` does not
  care what sits in `args[0]`.
- **Every start-anchored pattern silently stops matching at runtime.**
  `resource.argv like "git *"`, `resource.argv like "git push*"` and
  `resource.args.contains("git")` all match the fixture shape and never the real
  payload. In a `permit` that is **fail-safe** — the permit never fires, so the request
  falls through to default deny. In a `forbid` it **fails open**: the forbid never
  fires and any permit that did match still allows the launch. Since the README
  advertises `argv` globs as the *forbid-only* tool, the documented guidance was itself
  the fail-open hazard.
- The remedy is **D12** below: an `argv_tail` attribute that omits `args[0]`, giving
  anchored matching a sound target while `args`/`argv` stay faithful to what nono
  actually sends. The daemon never rewrites the payload.

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
| D12 | Expose `argv_tail` (the join of `args[1..]`) on `Command`; keep `args`/`argv` faithful to the payload nono sent | `args[0]` is a per-run shim path (§2 correction), so anchored patterns over `argv` never fire at runtime — fail-open in a `forbid`. `argv_tail` is the sound anchoring target and mirrors upstream's own `argv.iter().skip(1)` |
| D13 | Policy directory and audit log MUST live outside any tree the sandboxed agent can write; shipped defaults are home-anchored, never CWD-relative | Hot-reload turns a writable policy dir into a privilege-escalation path: the agent writes `permit(principal, action, resource);` and the PDP adopts it within a debounce. Proven end-to-end against the previous `./policies` default |

D9–D11 (empty policy dir refuses to start, policy ids carry file provenance, deny vs
broken are different signals) were recorded during the change proposal and live in
`openspec/changes/add-cedar-pdp-v1/design.md`; the numbering here continues from them.
D12 and D13 are post-implementation audit corrections.

### D12 — `argv_tail`: an anchoring target that excludes the shim path

`Command` gains one attribute:

```cedar
argv_tail: String,   // args[1..] joined by a single space; "" when args has < 2 entries
```

- `args` stays the `Set<String>` of exactly what nono sent (D6) and `argv` stays the
  join of *all* of it, `args[0]` included. Nothing is normalised away, so a policy can
  still see the shim path if it wants to.
- `argv_tail` is what anchored `like` patterns must use:
  `resource.argv_tail like "commit *"` instead of `resource.argv like "git commit *"`.
- The over-matching caveat carries over unchanged: `argv_tail` is still a flattened
  string, so it cannot tell `["push --force"]` from `["push", "--force"]`. It is
  therefore **forbid-only** for the same reason `argv` is, and the loader's
  `permit`-reads-`argv` lint must cover `argv_tail` too.
- `argv_tail` is derived *after* upstream's lossy UTF-8 filter, so a dropped non-UTF-8
  argument still changes the string. Set membership (`resource.args.contains(…)`)
  remains the primary tool; `argv_tail` exists for patterns set membership cannot
  express (adjacency, subcommand-plus-flag shapes) in `forbid` policies.
- An empty `argv_tail` (a bare `git`, or an `args` the lossy filter emptied) matches no
  pattern that begins with a literal. In a `permit` that is fail-safe. In a `forbid` it
  is one more reason a `forbid` is never the *only* control: the permits must be narrow
  enough that a non-firing `forbid` still leaves the request denied.

### D13 — policy directory and audit log live outside the agent-writable tree

The PDP's own state is part of its trust boundary:

- The policy directory is **hot-reloaded** (D7). Write access to it is write access to
  the decisions about the writer: dropping `permit (principal, action, resource);` into
  any `*.cedar` file there is adopted after the ~150 ms debounce, with only an INFO log
  line. The loader applies no ownership, mode or provenance check.
- The audit log is the compensating control for an unauthenticated webhook. Write
  access to it means the record of what was decided can be truncated or forged.

Therefore the shipped configuration MUST NOT put either inside a directory a sandboxed
agent can write — which rules out CWD-relative paths, because the smoke path runs
`nono run --allow-cwd` with `"workdir": {"access": "readwrite"}` in the repository root.
This was proven, not theorised: with the previous `policy_dir = "./policies"` default, a
process *inside* the sandbox overwrote both starter policy files, the PDP hot-reloaded
them, and a previously denied `git push --force` came back `allow`.

Shipped defaults this implies:

```toml
policy_dir = "~/.config/nono-cedar-pdp/policies"          # not "./policies"
audit_log  = "~/.local/state/nono-cedar-pdp/decisions.jsonl"   # not "./decisions.jsonl"
```

Both are home-anchored absolute paths after the tilde expansion the config loader
already performs, both sit outside any repository working tree, and the `just smoke`
recipe must read the audit log from the configured path rather than assuming the repo
root. Operators who relocate them keep the same invariant: the policy dir and the audit
log must not be reachable by the agent's write grants.

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
    command:   String,       // "git" — the command NAME (not args[0])
    args:      Set<String>,  // exact-membership tests only (D6); args[0] is a shim path
    argv:      String,       // space-joined ALL args incl. the shim path; unanchored globs only
    argv_tail: String,       // args[1..] joined — the target for anchored globs (D12)
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
- **`argv` must never be anchored at the start; `argv_tail` must be.** `args[0]` is a
  per-run shim path (§2 correction), so `argv like "git *"` cannot match a real
  payload — silently fail-open in a `forbid`. Anchored patterns go against
  `argv_tail` (`argv_tail like "commit *"`), which excludes `args[0]`; `argv_tail`
  inherits the same forbid-only over-matching caveat (D12).
- **`caller_kind` is derived** in the adapter (`caller == "session"`), not a wire
  field — the conformance test must not expect it from nono.
- **`arg_count`** counts args *after* upstream's lossy UTF-8 filter.
- **`HttpEndpoint.path` is the raw upstream path**, exactly as nono's proxy will send
  it (`crates/nono-proxy/src/reverse.rs:1159-1168`): not normalised, still
  percent-encoded. A prefix glob (`path like "/repos/*"`) is therefore satisfied by
  `/repos/../user/keys`, `/repos/%2e%2e/user/keys` and `/repos/..;/user/keys`, all of
  which resolve elsewhere at a normalising origin — a permit that fails open. The
  daemon does **not** normalise the path (that would decide, in the PDP, what the
  upstream will do); instead an ambiguous path is **denied before any policy is
  consulted**: any segment that is `.` or `..` after one percent-decode pass and after
  `;`-parameter stripping, or a malformed percent-escape, is a deny with a reason
  naming path ambiguity.
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
| Endpoint path with an ambiguous segment (`.`/`..`, before or after percent-decoding) or a malformed escape | `200` deny + reason, **policies not consulted** | a prefix glob over a raw path would otherwise permit `/repos/../user/keys`; normalising in the PDP would guess at the origin's behaviour |
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

All three backends above must exist in the **shipped example profile**, not only in
prose: a posture the docs name but the example profile does not define is a step an
operator cannot take (nono's validator rejects an `approval_defaults.backend` that
names an undefined backend). The example profile shipped with v1 omitted
`cedar-and-ask`, so the documented "paranoid" posture produced an invalid profile.

Run: `just serve` foreground; launchd plist for always-on (follow-up). `serve` reads a
config whose `policy_dir` and `audit_log` sit outside the agent-writable tree (D13).

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
