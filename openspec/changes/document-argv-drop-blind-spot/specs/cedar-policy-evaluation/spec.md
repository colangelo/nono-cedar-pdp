# cedar-policy-evaluation — delta for document-argv-drop-blind-spot

## MODIFIED Requirements

### Requirement: Report the argument-matching hazards that survive the schema

Removing the whole-argv attribute eliminates the anchoring hazard only. Three hazards
remain. The first two SHALL be reported as load-time diagnostics naming the policy
identifier (which carries its file), advisory rather than fatal. The third is not
detectable at load time or at decision time and SHALL be documented instead:

1. **Flattening.** `argv_tail` is still a joined string, so it cannot distinguish
   `["push --force"]` from `["push", "--force"]`, and `git commit -m "do not --force this"`
   still matches `*--force*`. Over-matching is fail-safe in a `forbid` and unsound in a
   `permit`. A test that **pins a whole token** is not affected: because `argv_tail` omits
   `args[0]`, a pattern anchored at the start whose literal ends at the separating space
   (`like "status *"`), a pattern with no wildcard at all, or an equality test
   (`== "status"`) all pin the first token of `args[1..]` — the subcommand — which is the
   one thing set membership cannot express, and is therefore the sound shape for a
   `permit`. The loader SHALL report a `permit` whose `resource.argv_tail` test is **not**
   such a pin, and SHALL NOT report one that is. A pattern that is anchored but stops
   mid-token SHALL be reported, because `like "diff*"` also matches
   `difftool --extcmd=<cmd>`, which executes `<cmd>`.
2. **Unmatchable `args` literals.** `args` still holds the per-run shim path, so an `args`
   membership test against a value containing a path separator can never match the
   program — fail-open when it appears in a `forbid`. The loader SHALL report such a test
   for either effect and direct the author at `resource.command`.
3. **Dropped arguments.** Upstream builds `args` by discarding every argv entry that is
   not valid UTF-8 rather than converting it, so such an entry is **absent** from `args`
   and from `argv_tail` alike — not displaced, absent. A rule cannot match an argument it
   cannot see, so a `forbid` naming an argument **fails open** for that invocation, and an
   anchored `permit` still fires because the tail reads as the bare subcommand. The
   dropped entry is dropped whole, so what matters is whether the matched bytes share an
   argv entry with the invalid bytes: membership on a flag occupying its own entry
   survives, while a glob over a `--flag=<value>` entry does not.

   This hazard SHALL NOT be reported as a lint, because no policy exhibits it — the defect
   is in the input, not in the rule. It SHALL NOT be presented as avoidable by careful
   authoring either: the post-drop request is byte-identical to a legitimate request that
   never carried the argument, so no policy, schema or code at this boundary can
   distinguish them, and any rule that denied one would deny the other. It SHALL be
   documented as an inherent limit of the decision input, naming what becomes
   unreliable, and it closes only upstream, by preserving arity.

#### Scenario: A permit with an unanchored argv_tail glob is reported

- **WHEN** the policy directory contains a `permit` whose condition is `resource.argv_tail like "*push*"`
- **THEN** loading reports the over-matching lint naming that policy, telling the author to anchor the pattern, and the policy set still loads

#### Scenario: A permit that pins a position is not reported

- **WHEN** a `permit` tests `resource.argv_tail == "status"`, or `resource.argv_tail like "status *"`, or a disjunction of both forms over several subcommands
- **THEN** no lint is reported, because the test pins the subcommand rather than searching the joined string
- **AND WHEN** the same `permit` also contains an unanchored test such as `resource.argv_tail like "*--porcelain*"`
- **THEN** the lint is reported, because the unanchored half is what can over-match into an approval
- **AND WHEN** a `permit` tests `resource.argv_tail like "diff*"`, which is anchored but stops mid-token
- **THEN** the lint is reported and names the token boundary, because that pattern also approves `git difftool --extcmd=<cmd>`

#### Scenario: An args membership test against a path literal is reported

- **WHEN** a policy tests `resource.args.contains("/usr/bin/git")`, or `resource.args.containsAny(["/bin/sh", "--force"])`, in either a `permit` or a `forbid`
- **THEN** loading reports a lint naming that policy, stating that `args[0]` is a per-run shim path no literal can match, and directing the author to `resource.command`
- **AND WHEN** the literal contains no path separator, such as `resource.args.contains("--force")`
- **THEN** no lint is reported

#### Scenario: A dropped argument is not reported as a policy defect

- **WHEN** the policy directory contains a `forbid` naming an argument, such as `resource.argv_tail like "*--exec-path*"`
- **THEN** no lint is reported for the dropped-argument hazard, because the rule is well formed and the loader has no request to inspect
- **AND** the documented guidance states that such a `forbid` does not fire when the argument's own entry carried invalid UTF-8, and that this is fail-open
