# Design: record-policy-set-provenance

## D1 — Hash the bytes the loader parsed, not the files on disk

The hash must describe **the set that is about to decide things**, not the directory as
it stands at some later instant. So it is accumulated inside `load_entries`, over the
same `text` each file's parse consumes, before `checked` builds `LoadedPolicies`.

Re-reading the directory afterwards to hash it would be a second moment with a second
result: on a busy directory the two can differ, and the record would then name content
the daemon never enforced. That is worse than no record — it is a false alibi.

Canonical framing, so the digest is unambiguous and order-independent of the filesystem:

```
for each loaded file, in the loader's existing sorted order:
    SHA256.update(u64_le(file_name.len()));  SHA256.update(file_name.bytes())
    SHA256.update(u64_le(contents.len()));   SHA256.update(contents.bytes())
```

Length prefixes because plain concatenation is ambiguous — `a.cedar`+`bc` and
`a.cedarb`+`c` would otherwise digest identically. File names included because a rename
with identical content is a real change to which policy id a decision reports (ids are
`<file stem>:<annotation-or-ordinal>`), and a hash that missed it would call two
genuinely different sets the same.

Recorded as lowercase hex with a `sha256:` prefix, so the algorithm is on the record and
a future change to it cannot be mistaken for a content change.

## D2 — `sha2` as a runtime dependency, and why ADR-001 does not forbid it

ADR-001 keeps `nono` a dev-dependency because a runtime dep would pull sigstore, x509 and
Keychain code into a security daemon for four serde structs. That reasoning is about
*weight and blast radius*, not about dependencies in general, and it does not reach here:
`sha2` is a small pure-Rust RustCrypto crate with no I/O, no TLS and no platform
integration.

Note the `libc` precedent in `Cargo.toml` does **not** apply: `libc`'s comment says it is
"already in the dependency tree transitively, so this pins no new code into the binary".
`sha2` is currently only in the tree via the `nono` **dev**-dependency, which never ships
in the binary. This is a genuinely new runtime dependency and is justified on its own
terms, not by pretending it is free.

**Rejected — `std::hash::DefaultHasher`.** No new dependency, and unusable: it is
SipHash, not a cryptographic hash, so an attacker choosing colliding content defeats the
whole point; and its output is explicitly not guaranteed stable across Rust releases, so
a recorded digest could stop matching after a toolchain bump. A forensic record that
silently changes meaning is worse than none.

## D3 — A `kind` discriminator on every line, including existing ones

Two record shapes in one JSONL stream need a discriminator. The alternative is
structural sniffing — "if it has `eval_us` it is a decision" — which is exactly the
guessing the existing fixed-key-set rule was written to prevent.

So `kind` is added to **both** shapes, `"decision"` and `"policy-set"`, and the spec rule
becomes per-kind: the key set is identical on every line *of a given kind*, and `kind`
tells you which. Existing decision lines gain one field and lose none, so a consumer
keying on `decision`/`matched` keeps working — the smoke recipe's greps included, which
is checked by running it.

**Rejected — a separate provenance file.** The tamper-evidence property comes from
*where the audit log lives* (outside every agent write grant, D13), and a second file
would have to re-derive the same protection: creation mode, rotation reattachment,
containment assertion. One stream, one set of guarantees, and provenance lines interleave
with the decisions they explain in the order things actually happened.

## D4 — Failed and refused reloads are recorded, with an outcome

The issue says "on every load and reload". Read narrowly that is successes only, which
would leave the case the issue exists for — a policy-directory compromise — exactly as
silent as it is now. The trust re-check refusal is *the* detection event, and today it
exists only on stdout, which `pdp-operations` already classifies as telemetry rather than
the record.

So the record carries an `outcome`:

| `outcome` | When | `content_hash` |
|---|---|---|
| `loaded` | bootstrap or reload adopted a new set | the adopted set's |
| `refused` | the pre-reload trust re-check refused | `null` — nothing was read |
| `failed` | the reload was attempted and errored | `null` — nothing was adopted |

`content_hash` is null on both non-adopting outcomes because there is no set to name, and
the generation recorded is the one still deciding. A reader can therefore always answer
"which content was live at time T" by taking the most recent `loaded` line.

The refusal and failure reasons are recorded as text. They are operator-facing strings,
so they get the same control-character escaping every other request-derived value gets —
a policy directory path is attacker-influenced in exactly the way the existing escaping
rule anticipates.

## D5 — The loader computes, the serve layer records

`cedar/` stays free of operational concerns so it can lift into a native upstream backend
(AGENTS.md, and the same reason the trust re-check lives in the watcher rather than the
engine). So:

- **`cedar::engine`** computes and exposes the hash. It is the only code that sees the
  bytes, and a digest of its own input is not an operational concern.
- **`main`** records the bootstrap load. It is also the only place that has the
  `isolation::check` warnings, which is why "did the at-risk warning fire" is recorded
  there and not derived deeper down.
- **`watcher`** records reloads, next to the trust re-check whose refusal it reports.

`watcher::spawn` therefore takes the audit handle. That is a signature change and the
honest one: a watcher that reloads policy without being able to record what it adopted
cannot implement this requirement.

## D6 — Startup ordering

`isolation::check` runs before the engine bootstraps; the audit log opens after. The
bootstrap provenance line is therefore written after the log opens, describing the
generation-1 load that already happened, carrying the warnings collected earlier. No
reordering of the security-relevant sequence — the checks still gate everything, and the
record is written as soon as there is somewhere to write it.

A load that *fails* at bootstrap still exits non-zero with the error, and writes nothing:
there is no audit log open yet, and inventing one at that point would mean creating a
file as a side effect of a refusal to serve.

## Risks

- **The hash names content, not authorship.** It is evidence for comparison, not an
  integrity control. Stated in the spec, the proposal and the module docs, because a
  field that looks like a signature is worse than no field — the same argument the
  `user_agent` field already carries.
- **One extra line per reload.** A directory under sustained churn now appends a
  `policy-set` line on each bounded-drain reload (~one per 2 s ceiling, #10). That is
  proportionate: those are exactly the events worth having a durable record of, and the
  volume is bounded by the same ceiling.
