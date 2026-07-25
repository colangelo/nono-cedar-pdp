# pdp-operations — delta for harden-policy-dir-isolation

## MODIFIED Requirements

### Requirement: Check the daemon's own state paths at startup, and do not overstate the checks

`serve` SHALL, before loading policies, opening the audit log or binding a socket,
refuse to start when the policy directory or any policy file the loader would load is
group- or world-writable, naming the path, the mode and the `chmod go-w` remedy; a
`.cedar` name the loader skips (an editor lock file or backup) SHALL NOT be a reason to
refuse. It SHALL also refuse to start when any **existing ancestor** of the resolved
policy directory or of the resolved audit log is group- or world-writable **without the
sticky bit**, naming the ancestor path and mode: a loosely-writable non-sticky ancestor
lets another local user rename the directory out from under the daemon and substitute
their own, so the mode of the directory itself never mattered. The sticky bit exempts
an *ancestor* — it prevents renaming or unlinking entries owned by someone else, which
is the ancestor attack — but SHALL NOT exempt the policy directory itself, where the
attack is creating a new `*.cedar` file and sticky does not prevent creation. It SHALL
also fail closed when the policy directory, a policy file, or an ancestor cannot be
inspected at all. Separately it SHALL warn — loudly, naming the risk — when the policy
directory or the audit log resolves inside the current working directory, so that the
repo-relative development configuration keeps working while being impossible to mistake
for a deployment.

Both checks SHALL be documented for what they actually buy, wherever they are
described:

- The group/world-writable refusal — on the paths themselves and on their ancestors —
  does **nothing** about the sandboxed agent. nono's sandboxes are path-based
  (Seatbelt, Landlock) and do not change uid, so the agent runs as the **same user**
  as this daemon and owner-write is exactly the access it has. The refusal defends
  against a **different and weaker** threat: another local user.
- The working-directory warning is a **heuristic proxy** and is wrong in both
  directions: it misses an absolute `policy_dir` that happens to sit inside a granted
  tree (on macOS the default profile groups grant write to `/tmp`, `$TMPDIR` and
  `/var/folders`), and it fires on a development run where no agent exists.
- The only control that actually prevents the escalation is the nono profile not
  granting write access to those paths, so the documentation SHALL give a reader the
  concrete procedure for checking a profile against that rule: the resolved write grants
  (`nono profile show <profile> --format manifest`, filtered to grants whose access
  includes write — which covers `filesystem.allow`/`write`/`allow_file`/`write_file`,
  `workdir.access: "readwrite"`, `--allow-cwd` and any group-supplied grant) plus every
  `command_policies.commands.*.from.*.sandbox.fs_write` and `fs_write_file` entry in the
  profile, which the resolved manifest does **not** include.

#### Scenario: A group-writable policy directory refuses to start

- **WHEN** `serve` is given a policy directory whose mode grants write to group or other
- **THEN** it exits non-zero without binding a port, and the message names the path, the mode and the `chmod go-w` remedy

#### Scenario: A loosely-writable non-sticky ancestor of the policy directory refuses to start

- **WHEN** `serve` is given a policy directory that is itself owner-only but has an existing ancestor whose mode grants write to group or other without the sticky bit
- **THEN** it exits non-zero without binding a port, and the message names the ancestor path and its mode

#### Scenario: A sticky world-writable ancestor is not a refusal

- **WHEN** the resolved policy directory or audit log sits below an ancestor whose mode is world-writable with the sticky bit set (`/tmp`-style, mode `1777`)
- **THEN** that ancestor is not a reason to refuse, because the sticky bit prevents another user from renaming or unlinking entries they do not own

#### Scenario: A loosely-writable non-sticky ancestor of the audit log refuses to start

- **WHEN** `serve` resolves an audit log whose existing ancestor chain contains a directory writable by group or other without the sticky bit
- **THEN** it exits non-zero without binding a port, and the message names the ancestor path and its mode — a substituted audit directory silently redirects the record of what was decided

#### Scenario: A loose file the loader ignores is not a refusal

- **WHEN** the policy directory contains a group-writable `.cedar` name the loader skips, such as an editor lock file
- **THEN** startup is not refused on account of that file

#### Scenario: A policy directory inside the working directory warns

- **WHEN** `serve` resolves `policy_dir` or `audit_log` inside the current working directory
- **THEN** it logs a warning that names the path, the profile keys that would grant an agent write access to it, that file modes cannot prevent the escalation because the sandbox runs as the same user, and that the check is a proxy that cannot read the profile — and then continues to serve

## ADDED Requirements

### Requirement: Re-check the state paths before adopting a reloaded policy set

The hot-reload path SHALL re-run the writability checks — the policy directory, every
policy file the loader would load, and the existing ancestor chain — before a freshly
loaded policy set replaces the active one. When the re-check refuses, the daemon SHALL
retain the last-known-good policy set, SHALL NOT adopt any file content read from the
offending directory, and SHALL log the refusal at ERROR naming the path and mode — the
same containment posture as a broken policy edit, because the in-memory set predates
the loosening and is the only trusted policy state left. The watch SHALL survive the
refusal: once the mode is repaired, a subsequent edit SHALL be adopted normally.

The re-check carries the same scope honesty as the startup check, in code comments and
operator documentation: it defends against other local users, and says nothing about
the sandboxed agent, which runs as the same user as the daemon and is bounded only by
its nono profile's write grants.

#### Scenario: A policy directory that becomes loosely writable mid-session is not adopted

- **WHEN** the policy directory, a loadable policy file, or an existing ancestor becomes group- or world-writable (non-sticky, for ancestors) while the daemon is running, and a filesystem event triggers a reload
- **THEN** the active policy set and its generation are unchanged, decisions keep flowing from the last-known-good set, and an ERROR log line names the offending path and its mode

#### Scenario: The watcher survives a reload-time refusal

- **WHEN** a reload was refused because a state path was loosely writable, and the operator then repairs the mode and edits a policy file
- **THEN** the subsequent reload is adopted, proving the refusal neither stopped the daemon nor killed the watch
