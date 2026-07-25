//! Startup diagnostics of the binary itself.
//!
//! Refusing to start is the right answer to a broken configuration, but an exit
//! that does not name the file or the subsystem that failed sends the operator
//! looking in the wrong place.
#![allow(clippy::unwrap_used)]

use std::process::Command;

/// The repo's own policy directory: valid, so startup gets far enough to fail on
/// the thing each test is about.
const POLICY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/policies");

fn serve_with(config_body: &str) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, config_body).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nono-cedar-pdp"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
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
