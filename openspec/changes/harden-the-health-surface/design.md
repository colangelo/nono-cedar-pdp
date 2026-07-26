# Design: harden-the-health-surface

## D1 — Remove the path, do not reduce it

The issue offers "drop the path (or reduce it to a basename/hash)". Removed outright.

A basename still names the directory an attacker is looking for (`policies`), and the
interesting half of the escalation is *where* it is, which a basename plus the handful of
plausible parents gives up anyway. A hash is worse than it looks: the space of real policy
directory paths is tiny and enumerable — the shipped default, the dev default, a few
`$HOME` shapes — so a hash is a lookup away from the path for exactly the local attacker
this is about, while *reading* as though it protects something.

Nothing needs the field. Its only in-tree consumer is a test, which D4 re-points at better
evidence.

## D2 — `last_reload` carries an outcome and a time, never a reason

The health surface answers "is this daemon serving what you think it is". That needs the
outcome and when. It does not need the reason, and the reason is exactly where the
disclosure would come back: reload errors quote the file they failed on
(`parsing /Users/…/policies/10-git.cedar: unexpected token`), which would re-introduce the
absolute path this change removes, through a field added in the same change.

So: `{"outcome": "refused" | "failed" | "loaded", "at": "<rfc3339>"}`, and the operator
follows the audit trail (`kind: "policy-set"`, which carries the reason and the file list)
or stdout for detail. Both of those sit behind filesystem permissions; `/healthz` asks
nothing of the caller.

`null` before any reload has been attempted, rather than a synthetic "loaded" entry
echoing the bootstrap: `loaded_at` and `generation` already describe the bootstrap load,
and a fabricated reload record would make "has anything happened since startup" unanswerable.

## D3 — One call updates both surfaces

`Provenance` already fans out the watcher's "here is what the load attempt did" to the
audit trail. It gains the health status cell, so a single call at each site updates both.

That is the point rather than a convenience: `/healthz` and the audit trail cannot
disagree about the last reload, because there is no code path that writes one without the
other. Two independent updates would be two things to keep in step, and the failure —
monitoring saying "loaded" while the trail says "refused" — would be silent and would
discredit both.

`arc_swap::ArcSwapOption` for the cell: already a dependency (it holds the policy set),
lock-free on the read path that every health check takes, and the write happens at most
once per reload.

## D4 — The symlink test needs a new observable, and gets a better one

`a_symlinked_policy_dir_is_resolved_before_serving` proves D7 — that `serve` resolves
`policy_dir` once, before the isolation checks, and hands the *resolved* path to the
engine, the watcher and every reload re-check — by asserting that `healthz.policy_dir`
reports the real directory rather than the configured symlink.

Removing the field would silently remove that proof. So it moves to the `files` array of
the `policy-set` audit line landed by `record-policy-set-provenance`.

This is stronger, not merely equivalent. `healthz.policy_dir` was the daemon *reporting
about itself* — a string it could get right while loading through a different chain. The
`files` array is the list of paths the loader actually opened. A daemon that resolved
correctly and a daemon that did not now differ in what they enumerate, which is the thing
D7 is actually about.

## D5 — Why not 503, kept where it will be read

In the proposal because it is the load-bearing judgement, and repeated here because a
future reader is more likely to reach for 503 than to look up why it was rejected.

A failed reload leaves a correct daemon serving a correct policy set. 503 invites a
restart; a restart re-runs the bootstrap load against the same broken directory; startup
fails and the process exits; nono gets connection refused and fails closed on everything.
The remedy would be many times worse than the condition — and it would fire precisely when
an operator has just made a typo in a policy file.

Zero policies stays 503 because that daemon really is not serving: every request is denied.

## Risks

- **Monitoring keyed on `policy_dir` breaks.** In-tree there is one consumer and it is a
  test (D4). The field is documented in the README, so the removal is a documented
  behaviour change rather than a silent one.
- **`last_reload` is process-local.** It does not survive a restart, and it is not meant
  to: the durable record is the audit trail, which is where a question about history
  belongs. `/healthz` answers about *now*.
