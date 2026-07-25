//! Startup diagnostics of the binary itself.
//!
//! Refusing to start is the right answer to a broken configuration, but an exit
//! that does not name the file or the subsystem that failed sends the operator
//! looking in the wrong place.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

/// The repo's own policy directory: valid, so startup gets far enough to fail on
/// the thing each test is about.
const POLICY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/policies");

fn serve_with(config_body: &str) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    serve_from(dir.path(), config_body, None)
}

/// Run `serve` with the config written into `config_dir`, optionally from a given
/// working directory. Returns (success, stdout + stderr) — `tracing` writes to
/// stdout and the startup failure to stderr, and a test about startup wants both.
///
/// Bounded by a deadline and killed if it outlives it: every test here is about a
/// startup that must *not* reach the listener, and a regression that lets one
/// through would otherwise hang the suite forever instead of failing it. A killed
/// daemon reports success, which is what makes the `assert!(!ok)` fire.
fn serve_from(
    config_dir: &std::path::Path,
    config_body: &str,
    cwd: Option<&Path>,
) -> (bool, String) {
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

    let config = config_dir.join("config.toml");
    std::fs::write(&config, config_body).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_nono-cedar-pdp"));
    command
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }

    let mut child = command.spawn().unwrap();
    let give_up_at = std::time::Instant::now() + DEADLINE;
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break Some(status),
            None if std::time::Instant::now() >= give_up_at => {
                child.kill().ok();
                break None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };

    let output = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    match status {
        Some(status) => (status.success(), text),
        None => (
            true,
            format!("{text}\n[still serving after {DEADLINE:?}; killed]"),
        ),
    }
}

/// A policy directory the loader accepts, built from the shipped pack so startup
/// gets past validation and fails (or warns) on the thing the test is about.
fn copy_shipped_policies(into: &Path) -> std::path::PathBuf {
    let dir = into.join("policies");
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(POLICY_DIR).unwrap() {
        let from = entry.unwrap().path();
        if from.extension().is_some_and(|e| e == "cedar") {
            std::fs::copy(&from, dir.join(from.file_name().unwrap())).unwrap();
        }
    }
    dir
}

/// `check` against the shipped policy directory, with the audit log in a temp dir so
/// the repo's own trail is untouched, and the same `[agents]` map the shipped
/// `nono-cedar-pdp.toml` carries — without it every decision is the baseline
/// unknown-agent deny rather than the decision under test. Returns (success, stdout).
fn check_fixture(fixture: &str) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "policy_dir = \"{POLICY_DIR}\"\naudit_log = \"{}\"\n\n[agents]\ncedar = \"claude-code\"\n",
            dir.path().join("decisions.jsonl").display()
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nono-cedar-pdp"))
        .arg("check")
        .arg("--config")
        .arg(&config)
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures").to_string() + "/" + fixture)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
    )
}

/// The operator-facing half of the endpoint-path fix: `check` on a saved payload has
/// to reproduce the production decision, including *why* it was refused. A reason
/// that only said "deny" would send the operator hunting for a missing permit.
#[test]
fn checking_a_traversal_endpoint_payload_denies_and_names_the_ambiguity() {
    let (ok, stdout) = check_fixture("endpoint-traversal.json");
    assert!(!ok, "a traversal path must exit non-zero: {stdout}");
    // `contains`, not `starts_with`: the daemon's tracing goes to stdout too, so the
    // WARN line about the refusal precedes the decision line.
    assert!(stdout.contains("DENY:"), "{stdout}");
    assert!(stdout.contains("ambiguous endpoint path"), "{stdout}");
    assert!(stdout.contains("/repos/../user/keys"), "{stdout}");
}

/// The command fixtures still decide the way the README says they do, so the same
/// invocation an operator copies from the docs keeps working.
#[test]
fn checking_the_command_fixtures_reproduces_the_documented_decisions() {
    let (ok, stdout) = check_fixture("git-status.json");
    assert!(ok, "{stdout}");
    assert!(
        stdout.contains("ALLOW: permitted by 10-git:git-read-only"),
        "{stdout}"
    );

    let (ok, stdout) = check_fixture("git-force-push.json");
    assert!(!ok, "{stdout}");
    assert!(
        stdout.contains("DENY: denied by 10-git:no-history-rewrites"),
        "{stdout}"
    );
}

#[test]
fn an_unopenable_audit_log_names_the_path_and_the_subsystem() {
    let (ok, stderr) = serve_with(&format!(
        "policy_dir = \"{POLICY_DIR}\"\naudit_log = \"/dev/null/decisions.jsonl\"\n"
    ));
    assert!(!ok, "startup must fail: {stderr}");
    assert!(
        stderr.contains("audit log"),
        "the message must name the subsystem: {stderr}"
    );
    assert!(
        stderr.contains("/dev/null/decisions.jsonl"),
        "the message must name the path: {stderr}"
    );
}

#[test]
fn a_non_loopback_bind_refuses_to_start() {
    let (ok, stderr) = serve_with(&format!(
        "policy_dir = \"{POLICY_DIR}\"\nbind = \"0.0.0.0:18182\"\n"
    ));
    assert!(!ok, "startup must fail: {stderr}");
    assert!(stderr.contains("loopback"), "{stderr}");
    assert!(stderr.contains("0.0.0.0:18182"), "{stderr}");
}

/// A policy directory a second local user can write is a directory in which
/// someone else can add `permit (principal, action, resource);`. It is not the
/// sandbox-escape defence — the agent runs as this same user — but it is a
/// refusal, not a warning, because nothing legitimate needs it.
#[test]
fn a_group_writable_policy_directory_refuses_to_start() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let policies = copy_shipped_policies(dir.path());
    std::fs::set_permissions(&policies, std::fs::Permissions::from_mode(0o770)).unwrap();

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\nbind = \"127.0.0.1:0\"\n",
            policies.display(),
            dir.path().join("decisions.jsonl").display()
        ),
        None,
    );
    assert!(!ok, "startup must fail: {output}");
    assert!(output.contains("group"), "{output}");
    assert!(output.contains("0770"), "the mode must be named: {output}");
    assert!(
        output.contains(&policies.display().to_string()),
        "the path must be named: {output}"
    );
    assert!(
        output.contains("chmod go-w"),
        "the operator needs the remedy: {output}"
    );
}

/// The repo-relative dev config keeps working — but it must be impossible to
/// mistake for a safe deployment, so the operator sees the risk named before any
/// decision is served. Paired with an unopenable audit log so the process exits
/// instead of listening: that also pins the ordering, since the warning has to
/// appear before the daemon gets as far as its audit log.
#[test]
fn a_policy_directory_inside_the_working_directory_warns_before_serving() {
    let dir = tempfile::tempdir().unwrap();
    let _policies = copy_shipped_policies(dir.path());

    let (ok, output) = serve_from(
        dir.path(),
        "policy_dir = \"./policies\"\naudit_log = \"/dev/null/decisions.jsonl\"\nbind = \"127.0.0.1:0\"\n",
        Some(dir.path()),
    );
    assert!(!ok, "the unopenable audit log must still fail: {output}");
    assert!(
        output.contains("SECURITY"),
        "the dev shortcut must be loudly named: {output}"
    );
    assert!(
        output.contains("policies"),
        "the warning must name the directory: {output}"
    );
    assert!(
        output.contains("fs_write"),
        "the warning must name the profile keys that grant the access: {output}"
    );
    assert!(
        output.contains("same user"),
        "the warning must say why file modes do not help: {output}"
    );
}
