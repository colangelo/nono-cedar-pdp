//! The binary's own subcommands: `validate`, `check` and `serve`.
//!
//! Refusing to start is the right answer to a broken configuration, but an exit
//! that does not name the file or the subsystem that failed sends the operator
//! looking in the wrong place. And the exit codes are a contract: `validate` is
//! documented as a CI/pre-commit gate and `check` as the way to reproduce a
//! production decision, so both are asserted here rather than re-implemented
//! in-process.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

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

    // The third thing the requirement asks `check` to report, next to the decision
    // and the matched policies: how long the evaluation took.
    assert!(
        stdout.contains(" µs)"),
        "the evaluation time must be reported: {stdout}"
    );

    let (ok, stdout) = check_fixture("git-force-push.json");
    assert!(!ok, "{stdout}");
    assert!(
        stdout.contains("DENY: denied by 10-git:no-history-rewrites"),
        "{stdout}"
    );
}

/// Run `validate` against `policy_dir`. Returns (success, stdout + stderr): the
/// count goes to stdout and the validation errors to stderr, and a test about the
/// gate wants both.
fn validate_dir(policy_dir: &Path) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\n",
            policy_dir.display(),
            dir.path().join("decisions.jsonl").display()
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nono-cedar-pdp"))
        .arg("validate")
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// A policy directory holding exactly `files`.
fn policy_dir_with(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).unwrap();
    }
    dir
}

/// `validate` is documented as the CI / pre-commit gate for policy changes, so a
/// regression to exit 0 would silently un-gate every policy edit. The errors have
/// to be printed too: an exit code alone tells an author nothing about what to fix.
#[test]
fn an_invalid_policy_directory_fails_validate_and_prints_the_errors() {
    // Schema violation: `cwd` is not an attribute the nono schema gives a Command.
    let schema_violation = policy_dir_with(&[(
        "bad.cedar",
        "@id(\"reads-cwd\")\npermit (principal, action == Nono::Action::\"launchCommand\", resource)\nwhen { resource.cwd == \"/tmp\" };\n",
    )]);
    let (ok, output) = validate_dir(schema_violation.path());
    assert!(
        !ok,
        "an invalid policy directory must exit non-zero: {output}"
    );
    assert!(
        output.contains("validation failed"),
        "the failure must say what kind it is: {output}"
    );
    assert!(
        output.contains("cwd"),
        "the author needs the offending attribute: {output}"
    );
    assert!(
        output.contains("bad:reads-cwd"),
        "the author needs the offending policy id: {output}"
    );

    // A file that will not parse at all: the message must name the file, since the
    // policy id does not exist yet.
    let unparseable = policy_dir_with(&[("broken.cedar", "permit (principal, action")]);
    let (ok, output) = validate_dir(unparseable.path());
    assert!(!ok, "{output}");
    assert!(
        output.contains("broken.cedar"),
        "the message must name the file: {output}"
    );

    // An empty directory is the deny-everything set the loader refuses.
    let empty = policy_dir_with(&[]);
    let (ok, output) = validate_dir(empty.path());
    assert!(!ok, "{output}");
    assert!(output.contains("no policies found"), "{output}");
}

/// The success half of the same gate: the count is what an author reads to confirm
/// the file they added was actually loaded, so it must be the real number rather
/// than any number.
#[test]
fn a_valid_policy_directory_reports_the_count_and_exits_zero() {
    let (ok, output) = validate_dir(Path::new(POLICY_DIR));
    assert!(ok, "the shipped pack must validate: {output}");

    let schema = nono_cedar_pdp::cedar::schema::load().unwrap();
    let expected = nono_cedar_pdp::cedar::engine::load_dir(Path::new(POLICY_DIR), &schema, 1)
        .unwrap()
        .set
        .num_of_policies();
    assert!(
        output.contains(&format!("OK: {expected} policies loaded and validated")),
        "the printed count must be the number of policies actually loaded ({expected}): {output}"
    );
}

/// A free loopback address, released before it is handed out. Racy in principle;
/// in practice nothing else claims an ephemeral port between these two lines, and
/// the alternative — a hard-coded port — collides with a developer's own daemon.
fn free_loopback_addr() -> SocketAddr {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

/// Startup must fail *before* the socket exists: a daemon that binds first and
/// validates second answers requests for the window in between, and nono treats a
/// connection refusal (fail closed) very differently from a 503 or a hang.
///
/// Proven three ways, because the process is gone by the time the assertions run:
/// the exit is non-zero and names the policy problem; the `listening` line the
/// daemon logs immediately after a successful bind never appears; and the address
/// is still free afterwards.
#[test]
fn a_policy_load_failure_exits_without_binding_a_port() {
    let policies = policy_dir_with(&[]);
    let addr = free_loopback_addr();
    let dir = tempfile::tempdir().unwrap();

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\nbind = \"{addr}\"\n",
            policies.path().display(),
            dir.path().join("decisions.jsonl").display()
        ),
        None,
    );
    assert!(!ok, "startup must fail: {output}");
    assert!(
        output.contains("no policies found"),
        "the message must name the problem: {output}"
    );
    assert!(
        output.contains(&policies.path().display().to_string()),
        "the message must name the directory: {output}"
    );
    assert!(
        !output.contains("listening"),
        "the daemon logs `listening` right after a successful bind, so this run bound \
         a port before failing: {output}"
    );
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_err(),
        "something is still listening on {addr} after a failed startup"
    );
    assert!(
        TcpListener::bind(addr).is_ok(),
        "{addr} is not free after a failed startup"
    );
}

/// A config with no `bind` has to reach the documented default, `127.0.0.1:8181`,
/// and the only way to see which address the daemon really tried is to make that
/// address unavailable: the failure then names it. Occupying the port rather than
/// listening on it keeps the test off a port a developer's own daemon may be using —
/// if that daemon already holds 8181 our bind simply fails, the precondition holds
/// anyway, and nothing of theirs is disturbed.
///
/// It also pins the ordering from the other end: the bind is the *last* thing
/// startup does, so a valid policy directory and a writable audit log leave the
/// address as the only thing left to fail on.
#[test]
fn a_config_without_a_bind_uses_the_documented_default_address() {
    const DEFAULT: &str = "127.0.0.1:8181";
    let dir = tempfile::tempdir().unwrap();
    let policies = copy_shipped_policies(dir.path());
    // Deliberately unused: holding it is the point, and it may already be held.
    let _occupied = TcpListener::bind(DEFAULT);

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\n",
            policies.display(),
            dir.path().join("decisions.jsonl").display()
        ),
        None,
    );
    assert!(
        !ok,
        "the default address is occupied, so startup cannot succeed: {output}"
    );
    assert!(
        output.contains(DEFAULT),
        "a config with no bind must resolve to {DEFAULT}: {output}"
    );
    assert!(
        output.to_lowercase().contains("address already in use"),
        "the failure must be the occupied default address, not something else — \
         otherwise this test proves nothing about which address was tried: {output}"
    );
}

/// The ordering proof the previous tests cannot give on their own: hold the port the
/// daemon is configured to bind, and the failure it reports still has to be the
/// policy one. A `bind` moved ahead of the policy load would report
/// `Address already in use` instead — a green suite with the guarantee gone.
#[test]
fn a_policy_load_failure_is_reported_before_the_port_is_touched() {
    let policies = policy_dir_with(&[]);
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\nbind = \"{addr}\"\n",
            policies.path().display(),
            dir.path().join("decisions.jsonl").display()
        ),
        None,
    );
    assert!(!ok, "startup must fail: {output}");
    assert!(
        output.contains("no policies found"),
        "the policy failure must be the one reported: {output}"
    );
    assert!(
        !output.to_lowercase().contains("address already in use"),
        "the daemon reached the listener before validating its policies: {output}"
    );
    drop(occupied);
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

/// Send one HTTP/1.1 request over a real socket and return the raw response.
/// `Connection: close` so the read ends at the response rather than on a timeout.
fn http(addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8_lossy(&response).to_string()
}

fn get(addr: SocketAddr, path: &str) -> String {
    http(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )
}

fn post(addr: SocketAddr, path: &str, body: &str) -> String {
    http(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

/// The whole startup sequence, then real requests over a real socket: every other
/// HTTP test in this repo drives the axum `Router` in-process, so nothing else
/// proves that `serve` binds anything, that it binds the *configured* address, or
/// that a decision made over a socket reaches the configured audit log.
///
/// Pinned to an ephemeral port rather than the documented default `127.0.0.1:8181`
/// deliberately: 8181 is where the README tells an operator to run their own
/// daemon, so claiming it in a test would fail on a developer's machine. The
/// default itself is pinned by `config::tests::loads_minimal_config_with_defaults`,
/// and the assertion below that the daemon answers on exactly the address its
/// configuration named closes the gap between the two.
#[test]
fn a_started_daemon_answers_healthz_and_approve_over_a_real_socket() {
    let dir = tempfile::tempdir().unwrap();
    let policies = copy_shipped_policies(dir.path());
    let audit_log = dir.path().join("state/decisions.jsonl");
    let addr = free_loopback_addr();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\nbind = \"{addr}\"\n\n[agents]\ncedar = \"claude-code\"\n",
            policies.display(),
            audit_log.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_nono-cedar-pdp"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for the listener rather than sleeping: a fixed sleep is either flaky or
    // slow, and an exit here is a startup failure the test should report as one.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut health = String::new();
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "the daemon exited during startup ({status}): {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            health = get(addr, "/healthz");
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let approve = post(
        addr,
        "/v1/approve",
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/git-status.json"
        ))
        .unwrap(),
    );
    let denied = post(
        addr,
        "/v1/approve",
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/git-force-push.json"
        ))
        .unwrap(),
    );

    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        logs.contains(&addr.to_string()),
        "the daemon must listen on the address its configuration named: {logs}"
    );
    assert!(
        health.starts_with("HTTP/1.1 200 OK"),
        "GET /healthz over a real socket: {health:?} (daemon log: {logs})"
    );
    assert!(
        health.contains("\"policies\":"),
        "health must report the loaded set: {health:?}"
    );
    assert!(
        approve.starts_with("HTTP/1.1 200 OK"),
        "POST /v1/approve over a real socket: {approve:?} (daemon log: {logs})"
    );
    assert!(
        approve.ends_with("{\"decision\":\"allow\"}"),
        "the permitted fixture must be allowed: {approve:?}"
    );
    assert!(denied.starts_with("HTTP/1.1 200 OK"), "{denied:?}");
    assert!(
        denied.contains("\"decision\":\"deny\""),
        "the forbidden fixture must be denied: {denied:?}"
    );
    assert!(
        denied.contains("10-git:no-history-rewrites"),
        "the deny reason must name the rule: {denied:?}"
    );

    // The decisions a socket produced must be on the record at the configured path,
    // which no in-process router test can show.
    let trail = std::fs::read_to_string(&audit_log)
        .unwrap_or_else(|e| panic!("nothing at the configured audit log: {e} (log: {logs})"));
    let lines: Vec<&str> = trail.lines().collect();
    assert_eq!(lines.len(), 2, "{trail}");
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["decision"], "allow");
    assert_eq!(
        first["matched"],
        serde_json::json!(["10-git:git-read-only"]),
        "{first}"
    );
    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(second["decision"], "deny");
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
