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

**`args[0]` is not the command name — and what it *is* depends on the launch path.**
`args` is the shim process's raw argv, so `args[0]` is whatever the caller execed with.
When nono launches the command itself it resolves the program with `which` against a
per-run shim directory (`<base>/nono-tool-sandbox-<pid>-<unix nanos>-<hex nonce>/shims/<command>`),
which is the absolute path shown above and changes every run; but a shell *inside* the
sandbox running `git status` execs that same shim with `args[0] = "git"`. So a pattern
anchored over the whole argv matches on one launch path and silently not on another —
nondeterministic, which is worse than consistently failing. The command **name** always
arrives separately, in `command`. This is why the schema exposes `argv_tail` (`args[1..]`)
and has no whole-argv attribute at all — see the caveats below.

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
just install-policies      # copy the starter pack into ~/.config/nono-cedar-pdp/policies
cargo run -- validate      # load + strict-validate the configured policy dir, then exit
cargo run -- check tests/fixtures/git-status.json      # evaluate one saved payload
just serve                 # run the daemon (release build, foreground)
just serve-dev             # same, but with the repo-relative dev config (warns loudly)
just smoke                 # end-to-end: a real `nono run` decided by Cedar
just mint-cert             # optional: the TLS pair for https on loopback
just smoke-tls             # end-to-end: a real `nono run` blocked when a squatter answers
```

`nono-cedar-pdp.toml`:

```toml
bind = "127.0.0.1:8181"          # loopback only; a non-loopback bind is a load error
policy_dir = "~/.config/nono-cedar-pdp/policies"
audit_log = "~/.local/state/nono-cedar-pdp/decisions.jsonl"   # created 0600, parents included

[agents]                         # nono approval-backend name -> Cedar Agent
cedar = "claude-code"
```

An optional `[tls]` table turns the listener into https — see
[Serving https on loopback](#serving-https-on-loopback). Absent, the daemon serves
plaintext exactly as it always has, and says so in one startup WARN.

A backend name absent from `[agents]` always resolves to the fixed identity
`unknown`, which the shipped baseline pack denies explicitly
(`00-baseline:no-unknown-agents`) — an unmapped backend is a loud deny, never a
quiet pass-through.

Both paths are outside any repository working tree **on purpose** — see
[Keep the policy directory out of the sandbox](#keep-the-policy-directory-out-of-the-sandbox),
which is the part of this README to read before deploying anything.
`nono-cedar-pdp.dev.toml` keeps the repo-relative shape (`./policies`,
`./decisions.jsonl`) for development; `serve` prints a loud `SECURITY:` warning for
every path that resolves inside its working directory, so the dev shortcut cannot be
mistaken for a deployment.

Endpoints:

- `POST /v1/approve` — the decision endpoint. Every request that gets as far as being
  a *question* is answered `200` with an allow or a deny; a malformed body gets *our*
  deny reason rather than axum's `400`, so the reason lands in nono's audit trail.

  Two headers are checked **before** the body is read, because a request that fails
  them cannot have come from nono:

  - `Content-Type: application/json` is required — nono's webhook client always sends
    it. Anything else, or nothing, is `415` and is **not** a decision: no deny reason
    (nono did not ask, so none is owed) and no audit line. Parameters are fine
    (`application/json; charset=utf-8`), and the type is compared case-insensitively.
  - A request carrying an `Origin` header is `403`, even with a correct content-type.
    nono never sends one; a browser always does. The two checks are independent on
    purpose, so neither is load-bearing alone.

  This is what closes the drive-by vector: a CORS-*simple* cross-origin POST — the
  kind a page you merely visit can make without your involvement — may only use
  `text/plain`, `application/x-www-form-urlencoded` or `multipart/form-data`, so
  requiring JSON forces a preflight, and this service sends no CORS headers, so the
  preflight fails and the POST never arrives. Both refusals are logged at `WARN` with
  the observed values, so you can see the endpoint being probed.

  Driving the endpoint by hand? Add the header — one flag:

  ```bash
  curl -s -X POST http://127.0.0.1:8181/v1/approve \
    -H 'Content-Type: application/json' \
    --data @tests/fixtures/git-status.json
  ```

- `GET /healthz` —
  `{"generation":3,"policies":5,"loaded_at":"2026-07-26T18:47:58.792669Z","last_reload":{"outcome":"refused","at":"2026-07-26T19:02:11.401Z"}}`.
  `503` if no policies are loaded, so "PDP broken" is distinguishable from
  "policy said no".

  `last_reload` is `null` until a reload has been attempted, and otherwise reports
  `loaded`, `refused` (the pre-reload trust re-check refused) or `failed` (invalid
  Cedar, an unreadable directory). **Alert on that field, not on the status code.** A
  daemon whose last reload failed still answers `200`, because it is serving correctly
  from its last-known-good set — that is the designed behaviour, and it is fail-closed.
  Reporting unavailable would invite your supervisor to restart it, and the restart
  re-runs the *startup* load against the same broken policy directory, fails and exits,
  after which nono gets connection refused and denies everything. The cure would be far
  worse than the disease, and it would fire exactly when you have just mistyped a policy
  file.

  **This endpoint deliberately reports no path and no reload-error text**, and that is
  not an oversight to be helpfully corrected. It is unauthenticated, like everything on
  the loopback listener, and your policy directory is the exact target of the
  policy-rewrite escalation the isolation checks exist to close; a reload error names the
  file it failed on, which gives away the same thing by another route. A basename or a
  hash is not a middle ground — the set of plausible policy directory paths is small
  enough to enumerate, so neither withholds anything from a local attacker while both
  read as though they do. For the detail, read the audit log's `policy-set` lines or the
  daemon's stdout; both sit behind file permissions.

Policies live in `policy_dir/*.cedar`, loaded in filename order. A matched policy is
reported as `<file stem>:<@id annotation or ordinal>`, which is what makes a deny
reason actionable:

```
$ cargo run -- check tests/fixtures/git-force-push.json
DENY: denied by 10-git:no-history-rewrites (1497 µs)
```

Two shapes of `*.cedar` file are **skipped, not loaded**: a name starting with `.` or
`#` (`.baseline.cedar`, Emacs's `.#10-git.cedar` lock symlink) and anything that is not
a regular file (a directory named `archive.cedar`). Failing the load on those would
brick every reload for as long as a policy file is open in an editor, so the daemon
passes over them — but never silently: each skip is a WARN naming the path and the
reason, because a skipped file is a policy you wrote that decides nothing. If a
`forbid` of yours is not firing, grep the log for `skipping a *.cedar file`.

Editing a policy file reloads the set in place (~150 ms debounce). A reload that
fails to parse or validate keeps the **last-good** set and does not advance the
generation, so a bad edit mid-session cannot deny-all a running agent. Startup with
an invalid or empty policy directory refuses to run — as does startup with a policy
directory (or policy file) that is group- or world-writable, since another local user
could otherwise add a `permit`.

The audit log carries two record shapes, and every line names its own in `kind`, so a
consumer selects on an explicit value instead of guessing from which keys are present.

Each decision appends one `kind: "decision"` line:

```json
{"kind":"decision","ts":"2026-07-25T14:36:37.569566Z","request_id":"tool-sandbox-approve-git-1784990197567145000",
 "session_id":"35abc0894927242e","backend":"cedar","agent":"claude-code",
 "principal":"Nono::Caller::\"session\"","action":"launchCommand",
 "resource":"git [/private/.../shims/git status]","child_pid":13820,
 "intercept_rule":"status","rule_label":null,"user_agent":"nono-cli/0.69.0",
 "decision":"allow","matched":["10-git:git-read-only"],
 "reason":"permitted by 10-git:git-read-only","eval_us":1670}
```

The key set is identical on every line *of a given kind*, so a consumer can tell "not
known" from "not recorded": a command line carries a null `rule_label`, an endpoint line
a null `intercept_rule`, and a line for a request that never parsed carries nulls for
`child_pid` and both rule fields.

Every load attempt appends a `kind: "policy-set"` line, so each decision can be tied to
the exact policy set that produced it — take the most recent `loaded` line before it:

```json
{"kind":"policy-set","ts":"2026-07-25T14:36:31.101204Z","outcome":"loaded","generation":1,
 "content_hash":"sha256:fa570171a2b4c8423763e6ed7135c4c63f9a6bb5c94ddcaa1923043695df39b5",
 "files":["/Users/you/.config/nono-cedar-pdp/policies/00-baseline.cedar",
          "/Users/you/.config/nono-cedar-pdp/policies/10-git.cedar"],
 "at_risk":false,"reason":null}
```

`outcome` is `loaded`, `refused` (the pre-reload trust re-check refused — see "Keep the
policy directory out of the sandbox") or `failed` (invalid Cedar, an unreadable
directory). The two that adopt nothing carry a null `content_hash` and `files`, because
there is no set to name, and record the generation *still deciding*. `at_risk` says
whether the startup isolation check raised its advisory warnings.

Attempts that adopt nothing are recorded deliberately: a refused reload is the detection
event for someone having changed your policy directory, and stdout is telemetry that
goes wherever you redirected it. This trail sits outside every write grant your nono
profile gives the agent, so an agent that tampers with the policy directory cannot erase
the record of having done so.

`content_hash` is **evidence, not an integrity control**. It is written by the same
process that read the files, so it lets you ask "is the policy directory still what
decided that request" and says nothing whatever about *authorship* — anyone who could
rewrite the policies could also have caused the hash of their version to be recorded.
Policy signing is the control, and is not built yet. Do not treat a matching hash as a
signature.

`user_agent` is what the caller presented, recorded verbatim — **evidence, not
verification**. Browser JavaScript cannot set `User-Agent` at all, so a line whose
agent is absent or unexpected is a signal worth having; a local process running as
your user sets it to anything it likes, so a line whose agent reads `nono-cli/0.69.0`
proves nothing. It does not authenticate the caller and is not a credential.

**Raising the log level puts this content into a stream that has none of the log's
protections.** At the default level the per-decision log line carries the identifiers
and the outcome only — `request_id`, `session_id`, `backend`, the action, allow/deny,
the matched policy ids and the timing — which is enough to correlate it with the audit
line. The rule is not specific to that one line: **every** default-level event about a
request may name identifiers and causes, never request-derived content. The two
refusals are where that bites, and both follow it — the WARN that refuses an ambiguous
endpoint path names the ambiguity it found and the `request_id`, not the path; the WARN
that refuses an unparseable body names our own fixed cause, not serde's error text,
which quotes the offending value verbatim. (Both are still in the deny reason nono
receives and in the audit line — this is about what reaches *stdout*.)

`RUST_LOG=debug` adds a second event, keyed by the same `request_id`, carrying the
resource summary: the command line an agent attempted, or the API path — query string
included — it requested. That is genuinely the first thing you want when a policy will
not match, but **DEBUG output inherits the audit log's sensitivity without its
permissions**: the log is `0600`, while stdout goes wherever you redirected it — a
shared journal, a log aggregator, terminal scrollback. The audit log is unchanged at
any level and remains the complete record.

The log is safe to rotate under a running daemon. An append handle survives a
`rename`, and its writes keep succeeding, so the naive version silently stops
recording anything readable at the configured path while `/healthz` stays green —
which is how a trail detaches without a single error. Before each record the daemon
compares the `(st_dev, st_ino)` of the configured path against the handle it holds and
reopens (0600) if they differ, so `logrotate`, an archiving `mv` or an `rm` all leave
the next decision recorded where the config says. A reopen that cannot succeed keeps
appending to the file already open and logs an error; an in-place truncation is
reported as a shrink. As everywhere in the audit path, none of this can change a
decision.

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
      "cedar-and-ask": {
        "type": "chain",
        "mode": "all",
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
decisions appear in the audit log with the expected policy ids. Note what it does *not*
do: it never points the daemon at this repository's `./policies`, because this profile
makes the repository root agent-writable — it copies the pack to
`~/.cache/nono-cedar-pdp/smoke`, proves no write grant reaches it, and reads its
assertions from the configured audit-log path. If nono reports that tool-sandbox is
inactive, run `nono setup` first; `nono why --command git --caller session --profile
cedar-pdp-smoke` shows whether the command policy resolves at all.

### Three rollout postures

Switch `approval_defaults.backend` — no dry-run mode exists in the PDP, because nono
already composes backends better than a flag could:

| Posture | Backend | Behaviour |
|---|---|---|
| Start here | `cedar-or-ask` | `chain` / `mode: "any"` — Cedar denies, then you get a terminal prompt. Nothing new is blocked; you learn where your policies are wrong. |
| Endgame | `cedar` | Cedar alone decides. Unattended runs work; a policy gap is a hard deny. |
| Paranoid | `cedar-and-ask` | `chain` / `mode: "all"` over `["cedar", "terminal"]` — Cedar **and** a human must allow. |

## Serving https on loopback

Optional, off by default, and the only thing that makes a port squatter's answer
useless to nono: nono's webhook client verifies the server certificate against the
**platform** trust store, so a process that cannot read the private key cannot be
believed, even when it wins the race for the port. What this does **not** buy is
[further down](#what-tls-does-not-buy) and deserves more of your attention than what
it does.

```bash
brew install mkcert && mkcert -install   # once per machine; the second needs an admin password
just mint-cert                           # ~/.config/nono-cedar-pdp/tls/{cert,key}.pem
```

Then the block in `nono-cedar-pdp.toml`:

```toml
[tls]                                             # absent ⇒ plaintext, exactly as before
cert = "~/.config/nono-cedar-pdp/tls/cert.pem"    # the leaf, plus any intermediates
key  = "~/.config/nono-cedar-pdp/tls/key.pem"     # 0600, and outside every read grant
```

and the scheme in the nono profile's approval backend:

```json
"url": "https://127.0.0.1:8181/v1/approve"
```

Both keys are required together: a `[tls]` naming only one of them is a load error,
not a partial application. And everything that can go wrong with the pair is a
**refusal to start**, never a quiet fall back to plaintext — unreadable, unparseable
or mismatched files, a key other local users can read, or a certificate the platform
verifier does not accept for the address in `bind`. An operator who believes the
transport is authenticated when it is not is worse off than one who never configured
it, because the belief is what the deployment was built on.

That last check runs **before the listener binds**, through the same crate nono's
client uses. So "will nono accept this certificate?" is answered at startup by the
code that decides it rather than by a runbook, and a daemon nobody could believe
never accepts a connection at all. It also catches what no minting procedure can: an
expired leaf, a CA removed from the trust store since, a `bind` moved to an address
the certificate does not cover.

### The URL names the literal address, never `localhost`

`https://127.0.0.1:8181/v1/approve` for the default `bind`. The minted certificate
covers `localhost`, `127.0.0.1` and `::1` together, so the hostname *works* — which
is exactly why this has to be said out loud.

On macOS `localhost` resolves `::1` before `127.0.0.1`. A daemon bound to
`127.0.0.1:8181` and a squatter bound to `[::1]:8181` therefore both start cleanly,
neither logs anything unusual, and every `https://localhost:8181` request reaches
the squatter. TLS still saves the outcome — the squatter has no key, so nono's
handshake fails and the command is blocked — but a URL whose listener is picked by
resolver order makes "which process am I talking to" unanswerable from the
configuration, which is a poor property in the one artifact whose whole purpose is
knowing who answered.

The daemon cannot enforce this; it never sees nono's URL. What it can do is refuse
to serve a certificate that does not cover the address it binds, and it does.

### Why `mkcert -install`, and why a certificate in a keychain is not the same thing

`mkcert -install` puts a local CA into the system trust store as a **user-added
trust anchor**. That status is what makes locally-minted certificates work at all: a
chain to a user-added anchor is exempt from the Certificate Transparency requirement
macOS applies to publicly-issued certificates, and from the 398-day validity cap
(the minted leaf runs about 27 months). A self-signed leaf dropped into a keychain
**is not a substitute** — it is not an anchor, so the CT policy still applies and
the verifier still refuses it. That is also why this daemon never generates a
certificate on first run: it would start happily and then fail every approval closed
for a reason nobody could see.

**Do not check any of this with `security verify-cert`.** Measured 2026-07-26: it
reports a Certificate Transparency failure for an mkcert leaf *with the mkcert CA
installed in the System keychain*, and reports the identical error for a name the
certificate does not carry at all — so it never reaches name matching, and answers
uniformly wrong in a way that reads as authoritative. The CLI applies a CT policy
the library path does not. The daemon's own startup self-test is the check.

### Without mkcert: an `openssl` fallback

The same shape with more steps — a local CA, a leaf signed by it, and the CA
installed as an anchor. A bare self-signed leaf is not a shortcut, for the reason
just above.

```bash
TLS_DIR="${TLS_DIR:-$HOME/.config/nono-cedar-pdp/tls}"
mkdir -p "$TLS_DIR" && chmod 700 "$TLS_DIR" && cd "$TLS_DIR"

# 1. The local CA. This is what gets installed, and what a bare leaf can never be.
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes -sha256 \
  -keyout ca-key.pem -out ca.pem -subj "/CN=nono-cedar-pdp local CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. The leaf. Neither of these failures shows up until the daemon's next startup,
#    after the admin-password step below. An address missing from the SANs is
#    refused for that address (NotValidForName). An EKU naming anything but
#    serverAuth is refused outright — measured; an EKU extension left out
#    altogether is merely unrestricted, so this line is what stops a leaf minted
#    for some other purpose from being reused here.
openssl req -newkey rsa:2048 -nodes -keyout key.pem -out leaf.csr \
  -subj "/CN=nono-cedar-pdp"
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 825 -sha256 -out cert.pem -extfile <(printf '%s\n' \
    "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
    "extendedKeyUsage=serverAuth" \
    "basicConstraints=critical,CA:FALSE")

chmod 600 key.pem ca-key.pem && chmod 644 cert.pem ca.pem
```

Then the step that needs an administrator — the one `mkcert -install` does for you:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain "$TLS_DIR/ca.pem"
```

`cert.pem` and `key.pem` are what the `[tls]` block names. `ca-key.pem` signs future
leaves and belongs nowhere near the daemon: anyone holding it can mint a certificate
this machine trusts for any name at all.

### What TLS does not buy

Written in the voice of the [accepted-risk register](docs/audits/), and for its
reason: a control that gets remembered by its headline is a control whose
preconditions get dropped.

- **Nothing against same-uid code that can read the private key.** Such a process
  completes a valid handshake and *is* this daemon, perfectly. Seatbelt and Landlock
  are path-based and do not change uid, so the sandboxed agent runs as the same user
  we do; what keeps the key away from it is the key's **location** relative to the
  read grants in your profile — the identical argument to the one for the policy
  directory, failing in the identical way if a profile grants read on the tree the
  key sits in. The key's mode, ownership and ancestor refusals defend against
  **other local users** only, like every other permission check here.
- **Nothing about nono's identity.** The webhook is unauthenticated in *both*
  directions and this closes one of them. nono still presents no credential, so a
  local process can still POST a decision request and forge an audit record here —
  see [what the header checks do and do not
  buy](#what-the-header-checks-do-and-do-not-buy). That direction needs an upstream
  change.
- **Not availability — that is traded away on purpose.** A squatter that takes the
  port first still denies service: this daemon fails to bind and exits loudly, or
  nono's handshake fails and every intercepted action is blocked. A fail-closed
  daemon prefers an outage to a silent bypass, which makes that the right direction,
  but it is a real cost rather than a free win.
- **No record of its own when a squatter is caught.** nono sees a *transport* error
  — `Sandbox initialization failed: approval webhook 'cedar' failed: …`, and the
  command exits 126 — not a denial carrying one of our reasons, because we were
  never asked. Nothing lands in this daemon's audit log either. Both outcomes are
  closed; they simply read differently, and whoever reads nono's audit after a squat
  will find a sandbox error rather than a policy decision.

`just smoke-tls` is the end-to-end proof of the paragraph above: it holds the port
with a certificate whose key it does not have, runs a real intercepted command under
`nono run`, and asserts the command was blocked by the transport path rather than by
a policy. It **skips loudly** when no local CA is installed, because a skip that
reads like a pass has stopped being a verification.

## Schema caveats you must know before writing policies

The schema is [`nono.cedarschema`](nono.cedarschema) — the load-bearing design
artifact, embedded in the binary. Six of its shapes are deliberate constraints, not
oversights.

1. **`args` is a `Set<String>`, so positional matching is unexpressible — and an
   argument that is not valid UTF-8 is not in it at all.** Upstream builds `args` with
   `filter_map(|a| from_utf8(a).ok())`, so such an entry is **dropped, not converted**:
   it is **absent from `args` and from `argv_tail`**, not merely displaced. Two separate
   consequences, and the second is the dangerous one.

   *Positions shift.* Cedar sets have no index access, so a policy physically cannot say
   "the second argument is `push`" — which is the intended shape. Test flag presence
   instead: `resource.args.contains("--force")`.

   *A rule that names an argument cannot match one it cannot see, and **in a `forbid`
   that is fail-open**.* An anchored `permit` still fires, because after the drop the tail reads
   as the bare subcommand. Whether a given rule survives depends on one thing — does it
   match bytes sharing an argv entry with the invalid bytes? Membership on a flag that
   **occupies its own argv entry** survives, because only the adjacent value is
   discarded (`git -c <non-UTF-8> status` still trips `args.contains("-c")`). A glob over
   a `--flag=<value>` entry does not: `git --exec-path=<dir whose name is not valid
   UTF-8> status` reaches this daemon as a bare `git status`, so the `forbid` never fires
   and the read-only permit approves it.

   **This is not something careful authoring avoids, and no policy you can write helps.**
   The post-drop request is **byte-identical** to one from a plain `git status`, so any
   rule denying the first denies the second — that is, denies the invocation the pack
   exists to approve. It closes only upstream, by **preserving arity** (reported as
   `GHSA-p385-fvxh-xvgf`); until then it is an accepted residual, recorded in
   [`docs/audits/`](docs/audits/) and pinned by a test in `tests/policies.rs`.
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
   bytes (overlong encodings can hide a `.`), or encoding nested more than 8 deep.
   Segments are separated by `/` **or `\`** — the WHATWG URL standard folds a backslash
   onto a slash for http(s), so `..\..\` is traversal too. The scan stops at the first
   raw `?` and nowhere else: a `..` inside the *query* is not ambiguous, because
   RFC 3986 defines path normalisation over the path component alone and `?path=../x`
   is an ordinary API parameter. A raw `#` does **not** stop it — an origin-form request
   target carries no fragment, so `/repos/x#/../user/keys` is denied while a plain
   `/issues/issue#5` is not. Unambiguous paths reach policy exactly as nono sent them.
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

## Keep the policy directory out of the sandbox

**The policy directory is hot-reloaded, so write access to it is write access to every
decision this daemon will make.** Dropping `permit (principal, action, resource);` into
any `*.cedar` file there is adopted after the ~150 ms debounce with nothing but an INFO
line. The audit log is the compensating control for an unauthenticated webhook, so write
access to *it* is the ability to truncate or forge the record of what was decided. This
is not theoretical: with the old `policy_dir = "./policies"` default, a process **inside
the nono sandbox** overwrote both starter policies through the smoke profile's own
grants, the PDP reloaded them, and a `git push --force` that had been denied came back
`allow`.

**The one control that prevents this is your nono profile.** Not file permissions: nono's
sandboxes are path-based — Seatbelt on macOS, Landlock on Linux — and neither changes
uid, so a command nono launches runs as the *same user* as this daemon. Every mode bit
the daemon could set, it sets against *other* users; against the sandboxed agent they buy
nothing. So the rule is:

> The policy directory and the audit log must never sit inside a path the sandbox profile
> grants write access to.

### Checking your own profile against that rule

Two places grant writes, and only one of them shows up in the resolved profile:

```bash
# 1. Session-sandbox grants, fully resolved: filesystem.allow / .write / .allow_file /
#    .write_file, workdir.access ("readwrite" grants the cwd of `nono run`), --allow-cwd,
#    and anything a `groups.include` entry adds.
nono profile show <profile> --format manifest \
  | jq -r '.filesystem.grants[] | select(.access | test("write")) | "\(.access)\t\(.path)"'

# 2. Per-command sandbox grants. These are NOT in the resolved manifest (verified against
#    nono 0.69.0), so read them out of the profile itself. A "." here is relative to the
#    command's working directory.
jq -r '.command_policies.commands // {} | to_entries[] as $c
       | $c.value.from // {} | to_entries[]
       | "\($c.key) from \(.key): fs_write=\(.value.sandbox.fs_write // [])"
         + " fs_write_file=\(.value.sandbox.fs_write_file // [])"' <profile>
```

Then check that neither your `policy_dir` nor your `audit_log` is one of those paths or
underneath one. `just smoke` runs exactly this comparison as an assertion, against
`examples/cedar-pdp-smoke.json`, before it starts the daemon — that profile grants the
sandboxed `git` `fs_write: ["."]` **and** `workdir.access: "readwrite"`, so the repository
root is agent-writable and the smoke daemon's state deliberately lives elsewhere
(`~/.cache/nono-cedar-pdp/smoke`).

Two traps worth knowing: on macOS the **default** profile groups grant write to `/tmp`,
`/private/tmp`, `$TMPDIR` and `/var/folders`, so a policy directory under any temp path is
agent-writable no matter how absolute it looks; and a grant on a parent directory is a
grant on everything below it.

### What the built-in checks actually buy

`serve` resolves its configured state paths once at startup, checks them before it loads
anything, and re-checks the policy directory on every hot reload. All of it is worth
having and none of it is the control above — do not read them as one:

- **Refusal on a group- or world-writable policy directory or policy file** (naming the
  path, the mode and `chmod go-w`). This defends against **other local users** — a shared
  group, a service account, anyone under `o+w` — which is a real but *weaker* threat than
  the sandboxed agent. It does nothing about the agent, which runs as the same uid and has
  owner-write by construction. (A user-private group counts as group-writable: the daemon
  cannot tell a private group from a shared one, so `chmod go-w` is the answer either way.)
  The refusal also says to **review the contents before tightening**: `chmod` does not
  undo content added or modified while the path was writable by others.
- **Refusal on a loosely-writable non-sticky *ancestor* of the policy directory or the
  audit log.** Write access to a parent is the power to rename the directory out from
  under the daemon and substitute another, so the mode of the directory itself never
  mattered. The sticky bit exempts an ancestor — it stops other users renaming or
  unlinking entries they do not own, so a `/tmp`-style `1777` chain is not refused — but
  it never exempts the policy directory itself, where the attack is *creating* a new
  `*.cedar` file and sticky does not restrict creation. Same threat model as above:
  other local users, not the agent.
- **Refusal on any state-path component owned by neither the daemon's user nor root.**
  Modes answer who may write through the permission system; ownership answers who may
  *change* the answer — a component another local user owns passes every mode test while
  that user keeps the power to loosen, rename or rewrite it, and the sticky bit stops
  renames of entries you do not own but not *pre-creating* a then-missing component (a
  policy directory under a `/tmp`-style ancestor, an audit log before its first record)
  and owning it. So the policy directory, every loadable policy file, every existing
  ancestor of both state paths, and the audit log file once it exists must be owned by
  the daemon's effective user or by root — root deliberately, because a root-installed
  pack this daemon cannot write is *stronger* than a user-owned one, system ancestors
  (`/`, `/Users`) are root-owned everywhere, and owner-or-root is the rule OpenSSH's
  `StrictModes` applies to `~/.ssh`. Ownership closes pre-creation, not in-place content
  history: a file this user owns whose content changed while its mode was loose is
  adopted once the mode is repaired, which is why the remedy above says review first.
  And it is still about other local users only — the sandboxed agent runs as the same
  uid and *is* the owner already.
- **The configured paths are resolved once, at startup, before any check.** The chain
  the checks walk and the chain the loader, the watcher and the audit log use are the
  same object, so a symlink on the configured path cannot be repointed after startup to
  redirect a reload to a tree the checks never saw; a symlink already pointing into
  another local user's tree at startup is caught by the ownership refusal on the
  resolved components. One residual, named rather than hidden: whoever can write a
  *lexical* component's holding directory can still, before startup, point the link at a
  stale tree this daemon's user genuinely owns — every resolved-chain check then passes,
  because the tree really is ours. That takes an unusual configured path (the shipped
  home-anchored defaults have no foreign-writable lexical components) and a useful stale
  tree to exist; the complete answer is the profile-derived check and policy signing on
  the backlog. Resolving paths defends the *check's* integrity against other local
  users — the sandboxed agent needs no symlink tricks against a path its profile already
  grants.
- **The same refusals re-run on every hot reload**, before a freshly read policy set can
  replace the active one. A policy directory that becomes loosely writable *while the
  daemon runs* is therefore not adopted silently: the last-known-good set keeps
  deciding, the refusal is logged at ERROR naming the path and mode, and repairing the
  mode plus one edit recovers without a restart. Two honest limits: the re-check runs
  just before the files are read, so a loosening inside that window is only caught at
  the next event; and a mode change alone does not wake the watcher — it is caught when
  the next policy-directory event fires.
- **A loud `SECURITY:` warning when `policy_dir` or `audit_log` resolves inside the current
  working directory** — the common case of "the tree the agent is working in", and what
  makes the dev config unmistakable. It is a **heuristic proxy, wrong in both directions**:
  it cannot read your profile, so it *misses* an absolute `policy_dir` that happens to sit
  inside a granted tree (the `$TMPDIR` case above), and it *fires* on a plain development
  run where no agent exists at all. The warning is not a substitute for the `jq` check.

The audit log's own *mode* is tightened to `0600` on open rather than being a refusal,
because a trail the daemon cannot keep private is still better recorded than not
recorded — but an audit log *owned by another user* refuses like any other component:
its owner could rewrite the record no matter what mode the open sets, and mode bits
were never a defence against the agent anyway (same uid, same rules as everything
above).

## Security posture

The webhook is **unauthenticated in both directions**. nono sends no credential, so
the PDP cannot authenticate the caller; over plaintext the PDP presents no credential
either, so nono cannot authenticate the decider, and any local process that binds
`127.0.0.1:8181` before the daemon does can answer `allow` to everything. Two
consequences:

- A non-loopback `bind` is a hard config error, not a warning. Being unreachable from
  other hosts is the only access control this daemon has by default.
- **https on loopback with a locally-trusted certificate** closes the outbound half,
  and ships: a port squatter without the key fails TLS, which nono treats as a
  transport error and therefore blocks. It is opt-in — see [Serving https on
  loopback](#serving-https-on-loopback), and read [what TLS does not
  buy](#what-tls-does-not-buy) before relying on it. The inbound half — verifying
  that the caller really is nono — is still the upstream ask: bearer-token or
  Unix-socket support in the webhook backend config.

Over plaintext, treat the port as part of the trusted local surface. Either way the
audit log is the record of what was actually decided — `matched` names the policy, so a
suspicious allow is traceable. That role is why the log is kept `0600`, why the daemon
notices a rotation instead of writing into a detached inode, and why its path belongs
outside every write grant in your profile (see
[Keep the policy directory out of the sandbox](#keep-the-policy-directory-out-of-the-sandbox)).

There is also a limit that no configuration here reaches: **the daemon can only decide on
the argv it is given, and one class of argument never arrives.** An entry that is not
valid UTF-8 is dropped upstream before the request is built, so an argument-naming
`forbid` does not fire for it (caveat 1 above). It is not mitigable at this boundary and
is tracked as an accepted residual in [`docs/audits/`](docs/audits/) — read that register
before concluding the pack denies everything it names.

### What the header checks do and do not buy

The decide endpoint refuses requests whose shape proves they did not come from nono —
no JSON content-type is `415`, an `Origin` header is `403` (see
[Endpoints](#quick-start) above) — and neither refusal writes an audit line, because a
request nono never made must not be able to put one there.

**But none of this authenticates nono.** The checks close the *remote* case completely:
a page you merely visit cannot reach the endpoint at all, because the content-type it
would need forces a CORS preflight this service fails. What remains is the local case,
and it remains fully open: a process running as your user presents
`Content-Type: application/json`, omits `Origin`, sets `User-Agent` to
`nono-cli/0.69.0`, and can therefore still forge an audit record that is
indistinguishable from a real one. The recorded `User-Agent` is evidence, **not
verification** — read it as "what was presented", never as "who this was".

That residual is inherent while the webhook carries no credential: nono 0.69.0's
webhook config has no field for a token or for custom headers, so a shared secret is
not merely unimplemented, it is impossible from this side. Closing it needs an upstream
change — a bearer token, or a unix socket where peer credentials can be read (macOS
exposes no peer uid for TCP loopback). Note also what is *not* here and why: there is
no rate limit, because nono maps any non-2xx to `Denied`, so a limit would convert
"someone can pollute the log" into "someone can deny your agent's legitimate work",
which is the worse failure for a fail-closed daemon.

## Docs

- **Design spec:** [`docs/superpowers/specs/2026-07-25-nono-cedar-pdp-design.md`](docs/superpowers/specs/2026-07-25-nono-cedar-pdp-design.md)
- **https on loopback (decisions T1–T11):** [`docs/superpowers/specs/2026-07-26-https-on-loopback-design.md`](docs/superpowers/specs/2026-07-26-https-on-loopback-design.md)
  — including the measured IP-SAN result and what the control does not close
- **Implementation plan:** [`docs/superpowers/plans/2026-07-25-nono-cedar-pdp-v1.md`](docs/superpowers/plans/2026-07-25-nono-cedar-pdp-v1.md)
- **ADR-001 — Rust + embedded `cedar-policy`:** [`docs/adr/ADR-001-rust-and-cedar-crate.md`](docs/adr/ADR-001-rust-and-cedar-crate.md)
- **Research:** [`docs/research/00-groundwork.md`](docs/research/00-groundwork.md) — groundwork
  from inspecting the upstream nono tree; [`docs/research/01-landscape.md`](docs/research/01-landscape.md)
  — landscape of self-hostable agent sandboxes and their policy-engine integration points
- **Change proposal & requirements:** [`openspec/changes/add-cedar-pdp-v1/`](openspec/changes/add-cedar-pdp-v1/)

## License

Apache-2.0, as declared in `Cargo.toml` (a top-level `LICENSE` file is still to be
added).
