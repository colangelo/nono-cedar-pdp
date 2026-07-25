// Baseline posture. Cedar is default-deny, so these only *narrow* behaviour.

// Nothing chained through another intercepted command may launch anything.
// `caller` is "session" for a direct agent launch, otherwise the invoking
// command's name.
@id("session-launches-only")
forbid (
  principal,
  action == Nono::Action::"launchCommand",
  resource
) unless {
  principal == Nono::Caller::"session"
};

// An unmapped approval-backend name resolves to Agent::"unknown". Deny it
// explicitly so a misconfigured `[agents]` table is loud rather than silent.
@id("no-unknown-agents")
forbid (principal, action, resource)
when {
  principal in Nono::Agent::"unknown"
};
