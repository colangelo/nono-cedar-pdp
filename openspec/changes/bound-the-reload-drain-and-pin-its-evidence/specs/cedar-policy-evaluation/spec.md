# cedar-policy-evaluation — delta for bound-the-reload-drain-and-pin-its-evidence

## MODIFIED Requirements

### Requirement: Hot-reload policies keeping the last known good set

The service SHALL watch the policy directory and reload on change. A successful reload SHALL atomically replace the active policy set and advance a generation counter. A failed reload SHALL retain the previously active set and log the error, so that a mid-session editing mistake cannot brick a running agent.

The watch SHALL debounce bursts, because one editor save produces several filesystem
events and each would otherwise be its own reload. That debounce SHALL have an **upper
bound measured from the first event of a burst**: the reload SHALL run no later than
that bound regardless of how long events keep arriving. A quiet-period debounce alone
terminates on a property of the event stream rather than of the daemon, so a continuous
stream — a misconfigured directory, an unrelated writer, a deliberate one — postpones
every reload for as long as it lasts, and a policy edit made during it is never picked
up. That is a liveness failure, not a correctness one: the postponed reload leaves the
last-known-good set deciding, which is fail-closed by construction. What it defeats is
hot-reload itself, silently, while the operator believes the edit took effect.

When the bound cuts a drain short, the service SHALL log it at WARN, naming that the
drain was truncated. Sustained event traffic in a policy directory is either a
misconfiguration or a symptom, and the operator SHALL NOT have to infer it from reloads
that merely seem late. WARN and not ERROR: nothing has failed and the active set is
intact.

The watch SHALL NOT filter events by whether the loader would load the named path.
A mode change on the policy directory produces an event naming the **directory**, and
the pre-reload trust re-check (see `pdp-operations`) depends on being woken by it;
filtering to `*.cedar` paths would defer that re-check until something happened to
touch a policy file.

#### Scenario: Valid edit takes effect

- **WHEN** a policy file is edited such that a previously permitted command is now forbidden
- **THEN** the generation advances and subsequent evaluations return the new decision

#### Scenario: Broken edit retains previous decisions

- **WHEN** a policy file is edited to contain invalid Cedar, or to violate the schema
- **THEN** the reload fails, the generation does not advance, and evaluations continue to use the last known good policy set

#### Scenario: A continuous event stream cannot postpone a reload indefinitely

- **WHEN** filesystem events arrive in the policy directory faster than the debounce quiet-period, continuously, and a policy file is edited such that a previously permitted command is now forbidden
- **THEN** the edit is adopted and subsequent evaluations return the new decision within the debounce upper bound, rather than waiting for the stream to stop

#### Scenario: A truncated drain is reported

- **WHEN** the debounce upper bound ends a drain that continuing events would otherwise have extended
- **THEN** a WARN log line records that the drain was cut short, so sustained traffic in the policy directory is visible to the operator rather than inferred
