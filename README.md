# nono-cedar-pdp

A fail-closed Cedar **policy decision point** for [nono](https://nono.sh)'s webhook
approval backend. nono stays the **policy enforcement point** — it owns the kernel
sandbox, the command shims and the credential proxy — and this daemon answers the one
question nono asks over HTTP: *may this launch/request proceed?* Decisions are made by
[Cedar](https://www.cedarpolicy.com/) policies loaded from a directory, strict-validated
against an embedded schema, hot-reloaded on edit, and appended to a JSONL audit trail.
Every error path — malformed body, unknown request variant, evaluation error, empty
match — resolves to **deny**. No code path returns allow on an error.

## The verified contract

Read from nono v0.69.0's source, not its docs, and pinned by
[`tests/conformance.rs`](tests/conformance.rs), which builds the payloads with the real
`nono` crate's own serde (a dev-dependency only — see
[ADR-001](docs/adr/ADR-001-rust-and-cedar-crate.md)).

nono `POST`s an envelope wrapping an internally-tagged request. A real `command`
payload — the `args[0]` value below is verbatim from an audit line of the end-to-end
smoke run:

```json
{"backend":"cedar","request":{"capability_type":"command",
 "request_id":"tool-sandbox-approve-git-1784990893285791000","command":"git",
 "args":["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git","status"],
 "caller":"session","intercept_rule":"status","reason":null,
 "child_pid":13820,"session_id":"35abc0894927242e"}}
```

**`args[0]` is an absolute per-run shim path, not the command name.** The shim forwards
its own `args_os()` and nono resolves the program with `which` against a shim directory
named `<base>/nono-tool-sandbox-<pid>-<unix nanos>-<hex nonce>/shims/<command>`, so the
value changes every run and no literal can match it. The command **name** arrives
separately, in `command`. This matters for policy authoring — see the caveats below.

and a real `endpoint` payload (the credential proxy hardcodes `session_id: "proxy"`
and `child_pid: 0`):

```json
{"backend":"cedar","request":{"capability_type":"endpoint","request_id":"proxy-endpoint-approval-github-api-1737",
 "route_id":"github-api","upstream":"https://api.github.com","method":"GET",
 "path":"/repos/foo/bar","rule_label":"endpoint_policy.approve[GET /repos/*]",
 "reason":"route requires approval","child_pid":0,"session_id":"proxy"}}
```

We reply with the stable friendly shape, never upstream's internal enum
representation:

```json
{"decision":"allow"}
{"decision":"deny","reason":"denied by 10-git:no-history-rewrites"}
```

Only `command` and `endpoint` ever reach a webhook in nono 0.69: `network` is never
constructed in production code and filesystem `capability` elevation is hardwired to
the terminal backend. Anything else — including a variant a future nono adds — is
classified `Unsupported` and denied. Wire structs deliberately do **not** use
`deny_unknown_fields`, so a nono upgrade that adds a field cannot brick every
decision; drift is caught by the conformance test instead. Config parsing is the
opposite: strict, because a typo in your own security config should fail loudly.

## Quick start

```bash
just --list                # every recipe
cargo run -- validate      # load + strict-validate ./policies, then exit
cargo run -- check tests/fixtures/git-status.json      # evaluate one saved payload
just serve                 # run the daemon (release build, foreground)
just smoke                 # end-to-end: a real `nono run` decided by Cedar
```

`nono-cedar-pdp.toml`:

```toml
bind = "127.0.0.1:8181"          # loopback only; a non-loopback bind is a load error
policy_dir = "./policies"
audit_log = "./decisions.jsonl"  # created 0600, parents included

[agents]                         # nono approval-backend name -> Cedar Agent
cedar = "claude-code"
# unknown_agent = "unknown"      # fallback for an unmapped backend name
```

Endpoints:

- `POST /v1/approve` — the decision endpoint. Always `200` with an allow or a deny;
  a malformed body gets *our* deny reason rather than axum's `400`, so the reason
  lands in nono's audit trail.
- `GET /healthz` — `{"generation":1,"policies":5,"policy_dir":"./policies"}`.
  `503` if no policies are loaded, so "PDP broken" is distinguishable from
  "policy said no".

Policies live in `policy_dir/*.cedar`, loaded in filename order. A matched policy is
reported as `<file stem>:<@id annotation or ordinal>`, which is what makes a deny
reason actionable:

```
$ cargo run -- check tests/fixtures/git-force-push.json
DENY: denied by 10-git:no-history-rewrites (1497 µs)
```

Editing a policy file reloads the set in place (~150 ms debounce). A reload that
fails to parse or validate keeps the **last-good** set and does not advance the
generation, so a bad edit mid-session cannot deny-all a running agent. Startup with
an invalid or empty policy directory refuses to run.

Each decision appends one line to the audit log:

```json
{"ts":"2026-07-25T14:36:37.569566Z","request_id":"tool-sandbox-approve-git-1784990197567145000",
 "session_id":"35abc0894927242e","backend":"cedar","agent":"claude-code",
 "principal":"Nono::Caller::\"session\"","action":"launchCommand",
 "resource":"git [/private/.../shims/git status]","decision":"allow",
 "matched":["10-git:git-read-only"],"reason":"permitted by 10-git:git-read-only","eval_us":1670}
```

## Wiring nono to it

Generate a profile skeleton so the base fields are whatever your nono version wants,
then merge in the approval wiring:

```bash
nono profile init cedar-pdp-smoke
```

The `command_policies` block (the full working profile is
[`examples/cedar-pdp-smoke.json`](examples/cedar-pdp-smoke.json)):

```json
{
  "command_policies": {
    "approval_backends": {
      "cedar": {
        "type": "webhook",
        "url": "http://127.0.0.1:8181/v1/approve",
        "timeout_secs": 5
      },
      "cedar-or-ask": {
        "type": "chain",
        "mode": "any",
        "backends": ["cedar", "terminal"]
      },
      "terminal": { "type": "terminal" }
    },
    "approval_defaults": { "backend": "cedar", "timeout_secs": 5 },
    "commands": {
      "git": {
        "from": {
          "session": {
            "sandbox": {
              "fs_read": [".", "/opt/homebrew", "~/.config/git"],
              "fs_write": ["."],
              "fs_read_file": ["~/.gitconfig"]
            }
          }
        },
        "intercept": [
          { "args": ["status"], "action": { "type": "approve", "timeout_secs": 5 } },
          { "args": ["push"], "action": { "type": "approve", "timeout_secs": 5 } }
        ]
      }
    }
  }
}
```

The approval wiring is the interesting half; the `sandbox` grants are just enough for
Homebrew's `git` to run on this Mac (`/opt/homebrew` for its dylibs, the two git config
paths so it does not abort on `~/.gitconfig`). Adjust those for your host — a Linux box
or Apple's `/usr/bin/git` needs different read grants, and `nono run` prints the exact
`--read` flags for whatever it denied.

Validate with `nono profile validate <file>` — nono's own `nono profile schema` is the
authoritative shape. An `intercept` `approve` action carries only `timeout_secs`, with
no `backend` field, so it routes through `approval_defaults.backend`; per-rule backend
routing exists only on invocation-policy rules (`invocation_policy.approve[].backend`).

Then run something intercepted:

```bash
nono run --allow-cwd --profile examples/cedar-pdp-smoke.json -- git status      # allowed by Cedar
nono run --allow-cwd --profile examples/cedar-pdp-smoke.json -- git push --force # denied by Cedar
```

`just smoke` does exactly this against a freshly started daemon and asserts both
decisions appear in the audit log with the expected policy ids. If nono reports that
tool-sandbox is inactive, run `nono setup` first; `nono why --command git --caller
session --profile cedar-pdp-smoke` shows whether the command policy resolves at all.

### Three rollout postures

Switch `approval_defaults.backend` — no dry-run mode exists in the PDP, because nono
already composes backends better than a flag could:

| Posture | Backend | Behaviour |
|---|---|---|
| Start here | `cedar-or-ask` | `chain` / `mode: "any"` — Cedar denies, then you get a terminal prompt. Nothing new is blocked; you learn where your policies are wrong. |
| Endgame | `cedar` | Cedar alone decides. Unattended runs work; a policy gap is a hard deny. |
| Paranoid | `cedar-and-ask` | `chain` / `mode: "all"` over `["cedar", "terminal"]` — Cedar **and** a human must allow. |

## Schema caveats you must know before writing policies

The schema is [`nono.cedarschema`](nono.cedarschema) — the load-bearing design
artifact, embedded in the binary. Six of its shapes are deliberate constraints, not
oversights.

1. **`args` is a `Set<String>`, so positional matching is unexpressible.** Upstream
   builds `args` with `filter_map(|a| from_utf8(a).ok())`: a non-UTF-8 argv entry is
   *silently dropped* and every later position shifts. Cedar sets have no index
   access, so a policy physically cannot say "the second argument is `push`". Test
   flag presence instead: `resource.args.contains("--force")`. (A runtime test for the
   lossy case is impossible from this side — the bytes are gone before we see them.)
2. **There is no whole-argv attribute — anchor on `argv_tail`.** `args[0]` is a per-run
   shim path, so a pattern anchored over the whole argv (`like "git commit *"`) can
   never match a real payload: fail-safe in a `permit`, **fail-open in a `forbid`**.
   Rather than warn about that, the schema does not offer the attribute at all — a
   policy that reads `resource.argv` **fails strict validation and will not load**.
   Anchor on `resource.argv_tail` (`args[1..]`, space-joined, `""` when there is no
   tail), which is exactly the slice nono's own matcher uses (`argv.iter().skip(1)`).
   For the same reason, `resource.args.contains("git")` — or any path literal — never
   matches the program: use `resource.command`. The loader warns when an `args`
   membership literal contains a `/`.
3. **Set membership cannot express POSITION — pin a subcommand with an anchored
   `argv_tail` test.** `resource.args.contains("status")` is true of
   `git -c core.fsmonitor=<cmd> status`, and git *runs* `<cmd>`: a "read-only git"
   permit written that way approves arbitrary code execution (this was the shipped
   pack's bug, fixed in [`policies/10-git.cedar`](policies/10-git.cedar)). Because
   `argv_tail` drops `args[0]`, its first token **is** the subcommand, so write
   `resource.argv_tail == "status" || resource.argv_tail like "status *"`. That also
   denies `git -c … status` — correct for a permit: a pattern that cannot prove the
   subcommand is first must not approve. Pair it with a `forbid` on the flags that
   execute code (`-c`, `--config-env`, `--exec-path`, `--upload-pack`,
   `--receive-pack`), so a later permit written with `contains` cannot resurrect the
   hole.
4. **UNANCHORED `argv_tail` globs are forbid-only.** Removing the whole-argv join
   fixed *anchoring*; it did not fix *flattening*, which is inherent to any joined
   string. A glob that begins with a wildcard over-matches: `git commit -m "do not
   --force this"` satisfies `resource.argv_tail like "*--force*"`, and no joined
   string can distinguish `["push --force"]` from `["push", "--force"]`. Over-matching
   is fail-safe in a `forbid` and unsound in a `permit`, so the loader **warns about a
   `permit` whose `argv_tail` test does not pin a whole token**. A pin is `== "status"`,
   a wildcard-free `like`, or a pattern anchored at the start whose literal ends at the
   separating space (`like "status *"`); `like "diff*"` is *not* — it stops mid-token and
   so also approves `git difftool --extcmd=<cmd>`, which executes `<cmd>`. Two hazards,
   then: anchoring is now structurally impossible, flattening is still a rule you have to
   follow.
5. **Endpoint paths arrive raw, and an ambiguous one is denied outright.** nono's proxy
   forwards the request target verbatim — unnormalised, still percent-encoded, query
   string included — so `resource.path like "/repos/*"` used to be satisfied by
   `/repos/../user/keys`, which GitHub-class origins resolve to `/user/keys`. The
   daemon does **not** normalise (that would change what your policy matches and would
   guess at the upstream's rules). Instead a path whose meaning depends on those rules
   is refused **before any policy is consulted**, with a reason naming the ambiguity:
   a `.`/`..` segment at any percent-decode depth (so `%2e%2e`, `%252e%252e` and
   `..;/` are covered), a malformed percent-escape, a decode that yields non-UTF-8
   bytes (overlong encodings can hide a `.`), or encoding nested more than 8 deep. A
   `..` inside the *query* is not ambiguous — it cannot move which resource the origin
   routes to. Unambiguous paths reach policy exactly as nono sent them.
6. **Endpoint requests carry no session identity.** nono's proxy hardcodes
   `session_id: "proxy"` and `child_pid: 0`. Rather than echo whatever the payload
   claims, the daemon *pins* `Nono::Caller::"proxy"` in `Nono::Session::"proxy"`, so a
   crafted payload naming a real session id cannot place the proxy caller inside that
   session's hierarchy and satisfy a session-scoped policy.

A seventh, related limitation: **nono sends a caller *label*, not a caller kind** —
`"session"` for a direct agent launch, otherwise the name of the intercepted command
that chained the launch. A profile that intercepts a command literally named `session`
therefore produces a payload indistinguishable from a direct launch. Disambiguating
needs a distinct field upstream.

## Security posture

The webhook is **unauthenticated in both directions**. nono sends no credential, so
the PDP cannot authenticate the caller; the PDP presents no credential, so nono cannot
authenticate the decider. Any local process that binds `127.0.0.1:8181` before the
daemon does can answer `allow` to everything. Two consequences:

- A non-loopback `bind` is a hard config error, not a warning. Being unreachable from
  other hosts is the only access control this daemon has.
- The first follow-up is **https on loopback with a locally-trusted certificate**: a
  port squatter without the key fails TLS, which nono treats as a transport error and
  therefore denies. Upstream ask: bearer-token or Unix-socket support in the webhook
  backend config.

Until then, treat the port as part of the trusted local surface, and remember that the
audit log is the record of what was actually decided — `matched` names the policy, so a
suspicious allow is traceable.

## Docs

- **Design spec:** [`docs/superpowers/specs/2026-07-25-nono-cedar-pdp-design.md`](docs/superpowers/specs/2026-07-25-nono-cedar-pdp-design.md)
- **Implementation plan:** [`docs/superpowers/plans/2026-07-25-nono-cedar-pdp-v1.md`](docs/superpowers/plans/2026-07-25-nono-cedar-pdp-v1.md)
- **ADR-001 — Rust + embedded `cedar-policy`:** [`docs/adr/ADR-001-rust-and-cedar-crate.md`](docs/adr/ADR-001-rust-and-cedar-crate.md)
- **Research:** [`docs/research/00-groundwork.md`](docs/research/00-groundwork.md) — groundwork
  from inspecting the upstream nono tree; [`docs/research/01-landscape.md`](docs/research/01-landscape.md)
  — landscape of self-hostable agent sandboxes and their policy-engine integration points
- **Change proposal & requirements:** [`openspec/changes/add-cedar-pdp-v1/`](openspec/changes/add-cedar-pdp-v1/)

## License

Apache-2.0, as declared in `Cargo.toml` (a top-level `LICENSE` file is still to be
added).
