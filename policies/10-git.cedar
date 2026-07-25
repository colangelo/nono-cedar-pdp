// Read-only git is fine.
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
// argv entries, so argument positions shift.
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
