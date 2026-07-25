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
- **Unanchored globs are unaffected.** `like "*--force*"` does not care what sits in
  `args[0]`: the shim path
  (`<base>/nono-tool-sandbox-<pid>-<nanos>-<hex>/shims/<command>`) contains no
  caller-controlled text, so it can neither create nor suppress such a match.
- **Every start-anchored pattern silently stopped matching at runtime.** Against the
  whole argv, `like "git *"`, `like "git push*"` and `resource.args.contains("git")`
  all matched the old fixture shape and never the real payload. In a `permit` that is
  **fail-safe** — the permit never fires, so the request falls through to default
  deny. In a `forbid` it **fails open**: the forbid never fires and any permit that
  did match still allows the launch. Since the README advertised whole-argv globs as
  the *forbid-only* tool, the documented guidance was itself the fail-open hazard.
- The remedy is **D12** below: the whole-argv `argv` attribute is **removed** and
  replaced by `argv_tail` (the join of `args[1..]`), which is the only sound target
  for an anchored glob. `args` stays faithful to the payload — `args[0]` included —
  so the daemon still never rewrites what nono sent; it just refuses to offer a
  policy hook that cannot work.

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
| D12 | Expose `argv_tail` (the join of `args[1..]`) on `Command` and **remove `argv`** (the whole-argv join) entirely; `args` stays faithful to the payload nono sent | `args[0]` is a per-run shim path (§2 correction), so anchored patterns over the whole argv never fire at runtime — fail-open in a `forbid`. `argv_tail` is the sound anchoring target and mirrors upstream's own `argv.iter().skip(1)`. `argv` had no use `argv_tail` does not serve as well, so it is made unexpressible rather than merely discouraged (same posture as D6) |
| D13 | Policy directory and audit log MUST live outside any tree the sandboxed agent can write; shipped defaults are home-anchored, never CWD-relative | Hot-reload turns a writable policy dir into a privilege-escalation path: the agent writes `permit(principal, action, resource);` and the PDP adopts it within a debounce. Proven end-to-end against the previous `./policies` default |
| D14 | The shipped read-only git permit pins the subcommand with an **anchored `argv_tail`** test, and a second, independent `forbid` covers git's code-executing flags (`-c`, `--config-env`, `--exec-path`, `--upload-pack`, `--receive-pack`) | Set membership cannot express position: `args.contains("status")` is true of `git -c core.fsmonitor=<cmd> status`, which git *executes*. Anchoring is the only expressible position pin (`args[0]` is gone from `argv_tail`, so its first token is the subcommand). Two independent layers, each proven to deny the exploit alone, so a future membership-shaped permit cannot resurrect it. Cost: `git -c … status` is denied — fail-safe, and a prompt under `chain`/`any` |
| D15 | Endpoint `path` stays **raw**; a path whose meaning depends on the upstream's normalisation is denied before any policy runs | `resource.path like "/repos/*"` was satisfied by `/repos/../user/keys` (and `%2e%2e`, `%252e%252e`, `..;/`). Normalising here would change what a policy matches *and* guess at which of many normalisation rules the upstream applies; refusing the ambiguity keeps `path` faithful and fails closed. Query strings, dots inside a segment, and a stray `%` below the first decode pass are deliberately not ambiguous |
| D16 | The audit sink revalidates the `(st_dev, st_ino)` of its path **before every record** and reopens on a mismatch; a failed reopen keeps writing to the handle already held | An append handle survives `rename`/`unlink` and its writes keep succeeding, so a rotation silently detached the trail: decisions were answered and recorded into an inode nothing can read at the configured path, with `/healthz` still green (proven by renaming the log under a running daemon). One `stat` per record is nothing next to a Cedar evaluation, and "periodic" would leave a window of unrecorded decisions. Dropping the line on a failed reopen would lose more than appending to the previous file, and neither path may change a decision |

D9–D11 (empty policy dir refuses to start, policy ids carry file provenance, deny vs
broken are different signals) were recorded during the change proposal and live in
`openspec/changes/add-cedar-pdp-v1/design.md`; the numbering here continues from them.
D12 and D13 are post-implementation audit corrections; D14–D16 come from the
adversarial security audit that followed.

### D12 — `argv_tail` replaces `argv`: one anchoring target, and it excludes the shim path

`Command` gains one attribute and loses one:

```cedar
argv_tail: String,   // args[1..] joined by a single space; "" when args has < 2 entries
// argv: String      — REMOVED. The whole-argv join is not expressible any more.
```

Why removal rather than deprecation (amended 2026-07-25, superseding the first draft
of this decision, which kept `argv` alongside `argv_tail`):

- **`argv` has no legitimate use that `argv_tail` does not serve at least as well.**
  Unanchored globs (`*--force*`) behave identically, because the shim path
  (`<base>/nono-tool-sandbox-<pid>-<nanos>-<hex>/shims/<command>`) contains no
  caller-controlled text and so can neither create nor suppress a match. Anchored
  globs work *only* against `argv_tail`. Matching `args[0]` itself is impossible (the
  value is per-run random) and would be an anti-pattern regardless, since argv[0] is
  caller-supplied and is never an identity claim.
- **Keeping it would keep a fail-open footgun whose only guard is a load-time
  WARNING.** That is exactly the posture D6 rejects for positional matching: make the
  unsound pattern *unexpressible*, not merely discouraged. With `argv` gone, a policy
  that references it fails strict validation — a structural guarantee instead of an
  advisory one, and one an operator cannot scroll past.
- **Removal is free now** (the change is unarchived and no operator policies exist)
  and becomes a breaking change the moment it ships.
- **`argv_tail` is not a workaround.** nono's own invocation matcher is
  `argv.iter().skip(1)` (`crates/nono-cli/src/tool-sandbox/policy.rs:243`), so
  upstream already treats argv[0] as not-an-argument. Our semantics track nono's,
  which also means a forged argv[0] from a chained caller cannot desynchronise policy
  from enforcement.

What the change does and does not fix — **two hazards, one now structural and one
still a rule**:

- **The anchoring hazard is eliminated.** An anchored pattern can only be written
  against `argv_tail`, where it matches the runtime payload.
- **The flattening hazard is not, and now lives on `argv_tail`.** It is inherent to
  any joined string: `argv_tail` still cannot tell `["push --force"]` from
  `["push", "--force"]`, so `git commit -m "do not --force this"` still matches
  `*--force*`. The **forbid-only** rule and the loader's
  permit-reads-a-joined-string lint therefore transfer to `argv_tail` intact.
  **Amended 2026-07-25 (D14, security audit): forbid-only applies to *unanchored*
  globs only.** Flattening is a property of *searching* the joined string; an
  **anchored** test (`argv_tail == "status"`, `argv_tail like "status *"`) instead
  *pins a position* — since `args[0]` is gone, the first token of `argv_tail` is the
  subcommand — and that is the only expressible way to say "the subcommand is X". The
  lint was narrowed to a permit whose `argv_tail` test is not such a pin.

The rest of D12, unchanged:

- `args` stays the `Set<String>` of exactly what nono sent (D6), `args[0]` included.
  Nothing is normalised away; a policy can still see the shim path via `args`, it just
  can never usefully match it — which the loader now warns about when an
  `args.contains(…)` literal carries a `/`.
- `argv_tail` is what anchored `like` patterns must use:
  `resource.argv_tail like "commit *"` (not `"git commit *"` — the command name is
  `resource.command`).
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

The repo-relative shape stays available as `nono-cedar-pdp.dev.toml` (plus
`just serve-dev`), because editing `./policies` and tailing `./decisions.jsonl` is how
this thing is developed. It is separated from the shipped config so the dev shortcut is
a deliberate choice rather than the default, and `serve` names the risk out loud on
every start with it.

**What the two startup checks buy — and what they do not.** `serve` refuses to start on
a group- or world-writable policy directory (or policy file), and warns when either path
resolves inside the current working directory. Neither is the control that stops the
escalation above, and the code, the specs and the README say so in the same words:

- **The refusal does nothing about the sandboxed agent.** Seatbelt and Landlock are
  path-based and do not change uid, so an agent nono launches runs as the *same user* as
  this daemon: owner-write is exactly the access it has, and no mode this process could
  set would take it away. The refusal covers a **different and weaker** threat — another
  local user (a shared group, a service account, anyone under `o+w`) who could otherwise
  add a `permit`. Worth refusing over; not a sandbox boundary.
- **The cwd warning is a heuristic proxy, wrong in both directions.** It cannot read the
  nono profile, so it *misses* an absolute `policy_dir` inside a granted tree — on macOS
  the default groups grant write to `/tmp`, `/private/tmp`, `$TMPDIR` and `/var/folders`,
  so a policy dir under any temp path is agent-writable and this check stays quiet — and
  it *fires* on a plain dev run where no agent exists at all.
- **The only real control is the profile.** The policy dir and audit log must not sit
  inside any path the sandbox profile grants write access to. That is checkable:
  `nono profile show <profile> --format manifest` lists every resolved grant (so
  `filesystem.allow`/`write`/`allow_file`/`write_file`, `workdir.access`, `--allow-cwd`
  and group-supplied grants all appear), and every
  `command_policies.commands.*.from.*.sandbox.fs_write`/`fs_write_file` in the profile
  has to be read separately, because the resolved manifest does not include per-command
  sandbox grants (verified against nono 0.69.0: a marker path added to `fs_write` appears
  in neither `--json` nor `--format manifest`). `just smoke` runs exactly that comparison
  as an assertion.

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
    argv_tail: String,       // args[1..] joined — the ONLY joined string; anchored tests pin
                             // the subcommand (D14), unanchored globs are forbid-only (D12)
    arg_count: Long,         // count of post-filter args, args[0] included (lossy-argv caveat)
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

- **Unanchored `argv_tail` globs are forbid-only; anchored ones pin a position
  (D14).** Cedar strings support only `like` globs; a substring pattern
  (`argv_tail like "*--force*"`) also matches when the text appears *inside a single
  argument* (`-m "do not --force"`), and a joined string cannot tell
  `["push --force"]` from `["push", "--force"]`. Over-matching is fail-safe in a
  `forbid` (spurious deny → terminal fallback prompts) but unsound in a `permit`, so
  the loader warns about a `permit` whose `argv_tail` test starts with a wildcard.
  A test anchored at the start — or an `==` — is the opposite case: it pins the first
  token of `args[1..]`, i.e. the subcommand, which set membership cannot express, and
  is the required shape for a read-only permit (D14). Exact flag tests use
  `resource.args.contains("--force")`.
- **There is no whole-argv attribute; anchored patterns go on `argv_tail`.** `args[0]`
  is a per-run shim path (§2 correction), so a pattern anchored over the whole argv
  could never match a real payload — silently fail-open in a `forbid`. Rather than
  warn about it, the schema does not offer it: a policy referencing `resource.argv`
  fails strict validation (D12 amendment). Anchored patterns use
  `resource.argv_tail like "commit *"`, which starts at `args[1]`.
- **`resource.args` can still hold the shim path, and no literal matches it.** `args`
  is faithful to the payload, so `args.contains("git")` or
  `args.contains("/usr/bin/git")` never matches the program — that is
  `resource.command`'s job. The loader warns when an `args` membership literal
  contains `/`, for both effects, because in a `forbid` this is the fail-open form.
- **`caller_kind` is derived** in the adapter (`caller == "session"`), not a wire
  field — the conformance test must not expect it from nono.
- **`arg_count`** counts args *after* upstream's lossy UTF-8 filter.
- **`HttpEndpoint.path` is the raw upstream path**, exactly as nono's proxy will send
  it (`crates/nono-proxy/src/reverse.rs:1159-1168`): not normalised, still
  percent-encoded. A prefix glob (`path like "/repos/*"`) is therefore satisfied by
  `/repos/../user/keys`, `/repos/%2e%2e/user/keys` and `/repos/..;/user/keys`, all of
  which resolve elsewhere at a normalising origin — a permit that fails open. The
  daemon does **not** normalise the path (that would decide, in the PDP, what the
  upstream will do, and would change what a policy matches); instead an ambiguous path
  is **denied before any policy is consulted**, with a reason naming the ambiguity and
  the path as sent (D15, `src/endpoint_path.rs`). Ambiguous means, over the target up
  to the first `?`/`#`: a segment that is `.` or `..` after `;`-parameter stripping at
  **any** percent-decode depth up to 8 — not just the first, since the number of decode
  hops downstream is unknown, so `%252e%252e` is refused too — a malformed
  percent-escape in the path *as sent*, a decode that yields non-UTF-8 bytes (overlong
  encodings hide a `.`), or nesting deeper than the bound. Deliberately **not**
  ambiguous: the query string (`?path=../x` cannot move the route), dots inside a
  segment (`/repos/foo..bar`), and a stray `%` that only appears after the first decode
  pass (`/x/50%25-done` → `50%-done`).
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
| Endpoint path with an ambiguous segment (`.`/`..` at any percent-decode depth) or an undecodable escape | `200` deny + reason naming the ambiguity, **policies not consulted** | a prefix glob over a raw path would otherwise permit `/repos/../user/keys`; normalising in the PDP would guess at the origin's behaviour |
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
