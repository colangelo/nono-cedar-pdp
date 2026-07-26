# nono-cedar-pdp — agent instructions

A fail-closed **Cedar Policy Decision Point** that answers nono's `WebhookApproval`
callbacks. [nono](https://github.com/nolabs-ai/nono) sandboxes AI agents with kernel
enforcement (Seatbelt/Landlock) and escalates blocked actions over an HTTP webhook; this
daemon decides, nono enforces. Integration uses nono's stock webhook backend, so **no fork
and no upstream change** are required.

## Three things that are easy to get wrong here

Each of these was a real defect found by audit, not a hypothetical.

1. **`args[0]` is a per-run absolute shim path**, not the command name —
   `/private/tmp/nono-tool-sandbox-<pid>-<nanos>-<hex>/shims/git`. The name arrives
   separately in `command`. The value changes every run, so no literal can match it, and a
   pattern anchored at the start of the whole argv silently never fires. That is fail-safe
   in a `permit` and **fail-open in a `forbid`**. The schema therefore has no whole-argv
   attribute at all: `resource.argv` fails strict validation. Anchor on `argv_tail`
   (`args[1..]` joined) instead. Note it is whatever the caller put in argv[0] — a shell
   inside the sandbox execs the same shim with `argv[0] = "git"` — so the failure is
   *nondeterministic*, which is worse than consistent.
2. **`argv_tail`'s first token is the subcommand, and that is the only way to pin one.**
   Set membership cannot express position, so `args.contains("status")` approves anything
   containing that word anywhere — `git -c core.fsmonitor=<cmd> status` is arbitrary code
   execution, and it shipped in the first starter pack. Anchored `argv_tail` tests are the
   sound shape for a `permit`. *Unanchored* globs over a joined string over-match inside a
   single argument (`git commit -m "do not --force this"` matches `*--force*`), so those
   stay forbid-only. The loader lints both mistakes.
3. **The policy directory and audit log must sit outside any tree a nono profile grants
   the sandboxed agent write access to.** The policy dir is hot-reloaded, so write access
   to it is write access to every decision about the writer. File permissions do not help:
   Seatbelt and Landlock are path-based and do not change uid, so the agent runs as the
   same user. Shipped defaults are home-anchored for this reason; `just serve-dev` is the
   repo-relative variant and warns loudly.

## Non-negotiables

- **Fail closed.** Any parse failure, unsupported request variant, evaluation error, or
  missing policy resolves to deny. No path may return allow on an error. Cedar evaluation
  errors force a deny even when the decision was `Allow`.
- **`nono` is a dev-dependency only** (ADR-001). A runtime dep would pull sigstore, x509
  and Keychain code into a security daemon for four serde structs. Drift is caught instead
  by `tests/conformance.rs`, which round-trips nono's own serialized types and asserts the
  exact key set — if it fails after a version bump, read the contract before touching it.
- **Wire parsing is lenient, config parsing is strict.** Unknown fields from nono are
  ignored (a nono upgrade must not brick every decision); unknown keys in our own config
  are a hard error (a typo must not be silently ignored).
- **Positional argument matching is unexpressible by construction** — `args` is a Cedar
  `Set`. Do not add an indexable form; upstream drops non-UTF-8 argv entries, so positions
  are untrustworthy.
- **Deny and broken are different signals.** Decision-shaped failures return `200` with an
  explicit deny reason (nono records our reason); a broken daemon returns `503`.

## Layout

| Path | What |
|---|---|
| `nono.cedarschema` | the load-bearing artifact — entity model and actions |
| `src/wire.rs` | serde mirrors of nono's contract; no logic |
| `src/query.rs` | `PolicyQuery` — the adapter-neutral internal boundary |
| `src/adapter/nono_webhook.rs` | envelope → `PolicyQuery` |
| `src/cedar/` | schema, per-request entity slices, policy loading, evaluation, reload |
| `src/decision.rs` · `src/audit.rs` | decision + reason; JSONL decision log |
| `src/server.rs` · `src/watcher.rs` | HTTP surface; policy hot-reload |
| `policies/` | starter policy pack (`just install-policies` copies it into place) |

`wire`, `query` and `cedar` are deliberately free of HTTP concerns so they can lift into a
native `CedarApproval` backend upstream later; `adapter/` and `server.rs` are the
disposable half.

## Working here

- `just` is the entry point (`just --list`). `just test`, `just lint` (clippy `-D
  warnings`; `unwrap`/`expect`/`panic` are denied outside tests), `just smoke` for the
  end-to-end proof against a real `nono run` — that one needs `nono setup` to have run.
- **TDD**: failing test first, watch it fail for the right reason, then implement.
- Changes go through **OpenSpec** (`openspec/changes/<name>/`): proposal → specs → design
  → tasks, then implement. `openspec validate --changes <name>` before committing.
- Conventional commits, granular. Always `main`, never `master`. Work on a branch.
- Backlog is **Gitea issues** on `ac/nono-cedar-pdp` (remote `internal`), labels declared
  in `backlog-schema.toml` — never invent a label, add it to the schema and sync.

## Docs

- `docs/superpowers/specs/2026-07-25-nono-cedar-pdp-design.md` — decisions D1–D13 with
  alternatives considered, the verified upstream contract, and the `args[0]` correction.
- `docs/adr/ADR-001-rust-and-cedar-crate.md` — Rust + embedded `cedar-policy`, and why
  `nono` is dev-only.
- `docs/research/` — groundwork and the ecosystem survey that establishes the gap.
- `openspec/changes/add-cedar-pdp-v1/` — proposal, design, four capability specs, tasks.
- `README.md` — operator-facing: quick start, nono profile wiring, rollout postures.
