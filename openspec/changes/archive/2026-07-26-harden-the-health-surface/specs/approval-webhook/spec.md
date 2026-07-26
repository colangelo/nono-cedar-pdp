# approval-webhook — delta for harden-the-health-surface

## MODIFIED Requirements

### Requirement: Report health distinctly from denial

The service SHALL expose `GET /healthz` reporting the loaded policy generation, the policy
count, the time the active set was loaded, and the outcome of the most recent reload
attempt. A broken decider SHALL be distinguishable from a policy denial: when no policies
are loaded the service SHALL respond `503` rather than a `200` denial, so nono's recorded
reason names the HTTP status.

The health surface SHALL NOT disclose the policy directory, any policy file path, or the
text of a reload error. The endpoint is unauthenticated like everything on the loopback
listener, and the absolute policy directory is precisely the target of the policy-rewrite
escalation the isolation checks exist to close; a reload error names the file it failed
on, which discloses the same thing by another route. Reducing the path to a basename or a
hash SHALL NOT be treated as satisfying this: the set of real policy directory paths is
small and enumerable, so neither withholds it from a local attacker while both read as
though they do. Detail belongs to the audit log and to stdout, which sit behind filesystem
permissions.

The most recent reload attempt SHALL be reported as an outcome — the set loaded, the
pre-reload trust re-check refused, or the reload failed — together with when it happened,
and SHALL be absent (explicitly null) until a reload has been attempted, rather than
fabricated from the bootstrap load, so that "has anything happened since startup" stays
answerable. It SHALL agree with the audit trail's provenance record by construction:
one recording call SHALL update both, because a health surface that disagrees with the
record discredits both.

A reload that failed or was refused SHALL NOT by itself make the service report
unavailable. Such a daemon is healthy — it answers correctly from the last-known-good
set, which is the designed behaviour — and reporting otherwise invites a restart, which
re-runs the bootstrap load against the same broken directory, fails startup and exits,
leaving nono to fail closed on every action. The remedy would be worse than the condition,
and would fire exactly when an operator has mistyped a policy file. Monitoring SHALL
therefore key on the reported outcome rather than on the status code.

#### Scenario: Healthy daemon reports its policy generation

- **WHEN** `GET /healthz` is called on a daemon with a loaded policy set
- **THEN** the response is HTTP 200 with the current generation, policy count and the load time of the active set

#### Scenario: Daemon with no policies reports unavailable

- **WHEN** the loaded policy set contains no policies
- **THEN** `/healthz` responds 503 and `/v1/approve` responds 503 instead of deciding

#### Scenario: The health surface names no path

- **WHEN** `GET /healthz` is called on any daemon, including one whose most recent reload was refused or failed
- **THEN** the response body contains neither the policy directory, nor any policy file path, nor the text of a reload error

#### Scenario: A refused reload is visible to monitoring

- **WHEN** a reload is refused by the pre-reload trust re-check, or fails on invalid Cedar, and `GET /healthz` is then called
- **THEN** the response reports the most recent reload outcome as refused or failed with the time it happened, while the generation and policy count continue to describe the last-known-good set that is still deciding

#### Scenario: A failed reload does not make the daemon report unavailable

- **WHEN** a reload has failed or been refused and the last-known-good set is still deciding
- **THEN** `/healthz` responds 200, because the daemon is serving correctly and a restart would re-run the same failing load and take the daemon down

#### Scenario: No reload attempted since startup

- **WHEN** `GET /healthz` is called on a daemon that has completed its bootstrap load and has not yet attempted a reload
- **THEN** the reported last-reload outcome is explicitly null rather than a synthesised record of the bootstrap load
