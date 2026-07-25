// Read-only git is fine.
//
// The command NAME comes from `resource.command`, never from args[0]: nono sends
// args as the shim's raw argv, so args[0] is an absolute per-run shim path
// (<base>/nono-tool-sandbox-<pid>-<nanos>-<hex>/shims/git) that no literal can
// match. There is deliberately no whole-argv attribute in the schema for the same
// reason; if you need an anchored glob, it goes on `resource.argv_tail`
// (= args[1..] joined) and only inside a `forbid` — see nono.cedarschema.
@id("git-read-only")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"launchCommand",
  resource
) when {
  resource.command == "git" &&
  (resource.args.contains("status") ||
   resource.args.contains("diff") ||
   resource.args.contains("log") ||
   resource.args.contains("show"))
};

// History rewriting is never approved automatically.
//
// NOTE: exact set membership, never a positional index — nono drops non-UTF-8
// argv entries, so argument positions shift. Membership over a flag is also exact
// where a joined-string glob would not be: `argv_tail like "*--force*"` would also
// fire on `git commit -m "do not --force this"`.
@id("no-history-rewrites")
forbid (
  principal,
  action == Nono::Action::"launchCommand",
  resource
) when {
  resource.args.contains("--force") ||
  resource.args.contains("--force-with-lease") ||
  resource.args.contains("--hard")
};
