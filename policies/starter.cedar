@id("allow-git-read-only")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" && resource.args.contains("status") };
