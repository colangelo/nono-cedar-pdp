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
