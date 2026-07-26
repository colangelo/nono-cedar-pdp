# Proposal: harden-the-health-surface

## Why

Gitea #7. `GET /healthz` is unauthenticated, like everything on the loopback listener,
and it has one field too many and two too few.

**It discloses the absolute policy directory** — precisely the target a local attacker
needs for the policy-rewrite escalation that epic #1 exists to close. Handing out the
path from an endpoint that asks nothing of the caller is free reconnaissance.

**It omits the load time**, which design §7 promised operators ("generation + load
time"). `loaded_at` has been written on every load since the engine was built and, as
of this change, has never once been read.

**And it cannot show a failed hot-reload.** A reload that is refused by the trust
re-check or fails on invalid Cedar keeps the last-good set deciding — correct, and
fail-closed — but `/healthz` answers `200` with a generation and a count that look
exactly like a healthy daemon. Monitoring cannot tell "serving the policies you wrote"
from "serving policies from an hour ago because every reload since has been refused".
That is the more valuable half of this issue: it is the operator-facing gap left by the
reload work in `harden-policy-dir-isolation`, `bound-the-reload-drain-and-pin-its-evidence`
and `record-policy-set-provenance`, all of which report only to stdout and the audit log.

## What Changes

- **`policy_dir` is removed** from the response. Not reduced to a basename or a hash —
  removed. A basename still names the directory, and a hash of a path is a lookup table
  away from the path for anyone who can guess the handful of plausible locations.
- **`loaded_at` is added**, RFC 3339 UTC, giving the field its first reader.
- **`last_reload` is added**: `{"outcome": …, "at": …}`, or `null` when no reload has
  been attempted since startup. `outcome` is `loaded`, `refused` or `failed`.
- **No reason text and no path on the health surface.** The outcome says *that*
  something was refused; the audit log and stdout say *what*. Putting the reload error
  string here would re-introduce the disclosure this change removes, since those errors
  quote the file they failed on.
- **`at_risk` is deliberately not exposed here.** The issue is explicit that risk
  signalling belongs in the audit log, and `record-policy-set-provenance` already put it
  there on every `policy-set` line.

## The status code stays 200 on a failed reload

Stated as a decision rather than an omission, because the obvious reading of "invisible
to monitoring" is "make it 503".

A daemon whose last reload failed **is healthy**: it is answering correctly from the
last-known-good set, which is the designed behaviour. Returning 503 would invite an
orchestrator to restart it — and a restart re-runs the *bootstrap* load against the same
broken policy directory, which fails startup and exits. Connection refused then makes
nono fail closed on every action. That converts "still deciding correctly" into a total
outage, which is strictly worse than the condition it was reacting to.

The existing 503-on-zero-policies is a different case and stays: a set with no policies
denies everything, so the daemon genuinely is not serving.

## Capabilities

### Modified Capabilities

- `approval-webhook`: "Report health distinctly from denial" loses the policy directory,
  gains the load time and the last-reload outcome, and gains the rule that the health
  surface carries no path and no reason text.

## Impact

- `src/server.rs`: `healthz` body; `AppState` gains the reload-status handle.
- `src/watcher.rs`: `Provenance` fans one call out to both the audit trail and the health
  status, so the two can never disagree about the last reload.
- `src/main.rs`: wiring.
- `tests/cli.rs`: **the symlink test needs a new observable.** It currently proves D7
  (the daemon serves from the resolved chain, not the configured symlink) by reading
  `healthz.policy_dir`. That observable is being removed, so it moves to the `files`
  array of the `policy-set` audit line — which is stronger evidence, being the paths
  actually loaded rather than a path the daemon reports about itself.
- `README.md`, design §7 pointer.
- Gitea: closes #7.
