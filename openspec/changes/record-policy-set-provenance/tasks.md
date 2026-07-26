# Tasks: record-policy-set-provenance

TDD throughout: failing test first, watched failing for the right reason, then the
implementation. `just test` must pass full and filtered; `just smoke` must still pass,
which is also what proves the `kind` addition did not break its greps on decision lines.

## 1. Content hash at load time

- [ ] 1.1 Add `sha2` to `[dependencies]` with a comment stating why ADR-001 does not forbid it and why the `libc` "already transitive" argument does **not** apply here (D2)
- [ ] 1.2 Failing test: two loads of an unchanged directory produce the same hash (determinism)
- [ ] 1.3 Failing test: editing one policy file's content changes the hash
- [ ] 1.4 Failing test: renaming a policy file without changing any byte of its content changes the hash — policy ids are `<file stem>:…`, so this is a real change to what a decision reports
- [ ] 1.5 Failing test: the framing is unambiguous — a set whose (name, content) pairs concatenate to the same byte string as another's must still hash differently (the length-prefix property)
- [ ] 1.6 Implement: accumulate inside `load_entries` over the same `text` each parse consumes; never re-read (D1). Expose as `LoadedPolicies.content_hash`, formatted `sha256:<lowercase hex>`

## 2. The `policy-set` record and the `kind` discriminator

- [ ] 2.1 Failing test: every decision line carries `kind: "decision"`
- [ ] 2.2 Failing test: a provenance line carries `kind: "policy-set"` and is parseable as JSON on its own line
- [ ] 2.3 Failing test: outcome `refused` and `failed` lines carry a `null` content hash and the generation still deciding (D4)
- [ ] 2.4 Failing test: the reason text on a refusal has control characters escaped on the **raw file bytes**, using DEL/C1 rather than `\u{1b}` — the trap noted in AGENTS.md is that a C0-only assertion stays green with the escaping removed
- [ ] 2.5 Implement `PolicySetRecord` and its writer in `audit.rs`, reusing the existing sink, reattach and failure-never-changes-a-decision paths rather than adding a second way to write

## 3. Wire it up

- [ ] 3.1 Failing test: the bootstrap load appends a `loaded` line at generation 1 carrying whether the at-risk warnings fired
- [ ] 3.2 Failing test (watcher): an adopted reload appends a `loaded` line whose hash differs from the previous one
- [ ] 3.3 Failing test (watcher): a reload refused by the trust re-check appends a `refused` line — the case that today exists only on stdout
- [ ] 3.4 Failing test (watcher): a failed reload appends a `failed` line
- [ ] 3.5 Implement: `watcher::spawn` takes the audit handle (D5); `main` records the bootstrap load after the log opens, carrying the `isolation::check` warnings (D6)
- [ ] 3.6 Module docs on `audit.rs` and `watcher.rs`: evidence, not an integrity control — the same standard the `user_agent` field already holds. No wording may read as a signature.

## 4. Documentation

- [ ] 4.1 README audit section documents both kinds, the per-kind fixed key set, and the evidence-not-verification framing for the hash
- [ ] 4.2 Check `tests/docs.rs` — it pins documented wording against shipped behaviour, so the README example may be load-bearing

## 5. Verify

- [ ] 5.1 Non-vacuity gate: break the hash (make it a constant) and confirm the drift tests go red; break the refusal recording and confirm 3.3 goes red. Commit first.
- [ ] 5.2 `just test` full and filtered (`cargo test --lib watcher`, `cargo test --lib audit`, `cargo test --lib engine`)
- [ ] 5.3 `just lint` clean
- [ ] 5.4 `just smoke` — proves the real decision lines still satisfy its greps after the `kind` addition, and shows a real provenance line in the trail
- [ ] 5.5 `openspec validate --changes record-policy-set-provenance`
- [ ] 5.6 Merge, archive, push to `internal` and `origin`, close #3
