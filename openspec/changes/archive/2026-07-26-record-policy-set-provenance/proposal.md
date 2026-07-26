# Proposal: record-policy-set-provenance

## Why

Gitea #3, under epic #1. Policy signing (#4) is unbuilt and needs a design; until it
exists, a policy-directory compromise is **silent in the durable record**. The audit log
can say which policy id decided a request, and cannot say which *content* that id had.
After a hot reload nothing in the trail answers "which policies were live when this
decision was made" — the generation is in memory and in stdout, and stdout is explicitly
telemetry rather than the record (`pdp-operations`: "Operational output is telemetry, not
the decision record").

This is the compensating control for a gap we cannot yet close, and it works precisely
because of D13: the audit log lives outside every write grant the agent has, so an agent
that tampers with the policy directory cannot erase the record of having done so.

The reload work that just landed sharpened the same point. The trust re-check refuses a
loosened policy directory and the bounded drain reports a truncated debounce — both at
ERROR/WARN on stdout, and **nowhere durable**. The one signal that says "someone changed
your policy directory in a way that was refused" currently lands in whatever the operator
redirected stdout to, which may be a shared journal, a log aggregator, or nothing.

## What Changes

- `LoadedPolicies` gains a **content hash** of the policy set: SHA-256 over the bytes the
  loader actually parsed, in a canonical framing that includes each file's name and
  length. Computed during the load, never by re-reading — a re-read is a different moment
  and could hash something the daemon never enforced.
- The audit log gains a second record shape, **`policy-set`**, carrying the content hash,
  the generation, the file list, the outcome, and whether the startup at-risk warnings
  fired. Appended on the bootstrap load and on every reload.
- Every audit line gains an explicit **`kind`** field (`"decision"` or `"policy-set"`).
  Two shapes in one stream need a discriminator; without one a consumer has to sniff
  keys, which is the guessing the existing fixed-key-set rule exists to prevent.
- **Refused and failed reloads are recorded too**, not only successful ones. This is
  deliberately broader than the issue's wording ("on every load and reload") and is the
  heart of its stated purpose: a refused reload *is* the compromise signal. Recording only
  successes would leave the interesting case exactly as silent as before.
- A new runtime dependency, `sha2`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `decision-audit-log`: "Record every decision as one JSONL line" and "Audit lines are
  self-sufficient for review" are extended for a second record kind — the `kind`
  discriminator, the fixed key set becoming per-kind, and the provenance line's contents
  and outcomes.

## Impact

- `Cargo.toml`: `sha2` added to `[dependencies]`.
- `src/cedar/engine.rs`: hash computed in the loader; `LoadedPolicies.content_hash`.
- `src/audit.rs`: `kind` on the decision record; new `PolicySetRecord` and its writer.
- `src/main.rs`: records the bootstrap load, carrying the isolation warnings.
- `src/watcher.rs`: records reload success, reload failure and trust refusal.
- `README.md`: the audit-line section documents both kinds.
- Gitea: closes #3. Epic #1 stays open (#4 signing, #2 profile verification remain).

## Not done

- **Nothing is added to `/healthz`.** The issue is explicit, and #7 is about that surface
  over-disclosing already. Provenance goes to the trail an attacker cannot rewrite, not
  to an unauthenticated endpoint.
- **No signature, and no claim of one.** A hash recorded by the same process that loaded
  the files detects *drift you can later compare against*, and proves nothing about
  authorship. It is forensic evidence, not an integrity control; #4 is the control. No
  wording in code, spec or docs may blur that.
