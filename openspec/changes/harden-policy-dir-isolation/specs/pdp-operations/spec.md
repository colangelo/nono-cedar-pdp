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
attack is creating a new `*.cedar` file and sticky does not prevent creation.

Mode bits alone are not the whole check, because an owner may change them at will:
`serve` SHALL also refuse to start when the policy directory, a loadable policy file,
an existing ancestor of either state path, or the audit log file itself (when it
exists) is **owned by neither the daemon's effective user nor root**, naming the path
and the owning uid. A component another local user owns passes every mode test while
that user retains the power to loosen, rename or rewrite it — the sticky bit stops
renames of entries you do not own, but it does not stop an attacker *pre-creating* a
component and owning it, and ownership is the check that closes that half.

The refusal checks and the policy loader SHALL operate on the **same resolved path**:
`serve` resolves the configured `policy_dir` (and the existing prefix of `audit_log`)
once at startup, before the checks, and every later load, watch and reload re-check
uses the resolved path — so a symlink on the configured path cannot be repointed after
startup to redirect a load to a tree the checks never saw, and a symlink already
pointing at an attacker-owned tree is caught by the ownership refusal on the resolved
components.

A writability refusal's remedy text SHALL NOT overpromise: alongside `chmod go-w` it
SHALL tell the operator that content added or modified while the path was writable by
others is not undone by tightening the mode, so the directory's contents need review
before the remedy is applied.

It SHALL also fail closed when the policy directory, a policy file, or an ancestor
cannot be inspected at all. Separately it SHALL warn — loudly, naming the risk — when
the policy directory or the audit log resolves inside the current working directory, so
that the repo-relative development configuration keeps working while being impossible
to mistake for a deployment.

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

#### Scenario: A state-path component owned by another user refuses to start

- **WHEN** the policy directory, a loadable policy file, an existing ancestor of either state path, or an existing audit log file is owned by a uid that is neither the daemon's effective user nor root — for example a policy directory another local user pre-created under a sticky world-writable ancestor, with modes that look tight
- **THEN** `serve` exits non-zero without binding a port, and the message names the path and the owning uid, because an owner can loosen, rename or rewrite the component regardless of its current mode

#### Scenario: A symlinked policy path is resolved once, before the checks

- **WHEN** `policy_dir` is configured through a symlink
- **THEN** the daemon resolves the path before the startup checks and uses the resolved path for loading, watching and every reload re-check, so repointing the symlink after startup does not redirect any later load to a tree the checks never inspected

#### Scenario: The writability remedy warns about content changed while loose

- **WHEN** a writability refusal is reported for the policy directory or a policy file
- **THEN** the message tells the operator that tightening the mode does not undo content added or modified while the path was writable, so the contents need review before `chmod go-w` is applied

#### Scenario: A loose file the loader ignores is not a refusal

- **WHEN** the policy directory contains a group-writable `.cedar` name the loader skips, such as an editor lock file
- **THEN** startup is not refused on account of that file

#### Scenario: A policy directory inside the working directory warns

- **WHEN** `serve` resolves `policy_dir` or `audit_log` inside the current working directory
- **THEN** it logs a warning that names the path, the profile keys that would grant an agent write access to it, that file modes cannot prevent the escalation because the sandbox runs as the same user, and that the check is a proxy that cannot read the profile — and then continues to serve

## ADDED Requirements

### Requirement: Re-check the state paths before adopting a reloaded policy set

The hot-reload path SHALL re-run the writability and ownership checks — the policy
directory, every policy file the loader would load, and the existing ancestor chain —
before a freshly loaded policy set replaces the active one. When the re-check refuses, the daemon SHALL
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
