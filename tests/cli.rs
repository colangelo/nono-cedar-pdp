//! The binary's own subcommands: `validate`, `check` and `serve`.
//!
//! Refusing to start is the right answer to a broken configuration, but an exit
//! that does not name the file or the subsystem that failed sends the operator
//! looking in the wrong place. And the exit codes are a contract: `validate` is
//! documented as a CI/pre-commit gate and `check` as the way to reproduce a
//! production decision, so both are asserted here rather than re-implemented
//! in-process.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{BufRead, Read, Write};
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

/// The offline path exercises a multi-token `intercept_rule` too. JSON fixtures
/// cannot carry comments, so the upstream citation lives here: real nono builds
/// the rule label by joining the matched intercept rule's args with spaces
/// (nolabs-ai/nono `crates/nono-cli/src/tool-sandbox/policy.rs`,
/// `ResolvedInterceptAction::rule_label()` — upstream's own test asserts
/// `"push --force"`), so a corpus of single tokens would green-light a consumer
/// that assumes one word.
#[test]
fn checking_a_multi_token_intercept_rule_fixture_reproduces_the_decision() {
    let (ok, stdout) = check_fixture("git-force-push-multi-token-rule.json");
    assert!(!ok, "{stdout}");
    assert!(
        stdout.contains("DENY: denied by 10-git:no-history-rewrites"),
        "a space-joined rule must parse and decide like any other: {stdout}"
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

// `free_loopback_addr` — bind `127.0.0.1:0`, read the port, release it, hand it
// out — used to live here and has no replacement on purpose. It cannot hand out a
// *reserved* port: releasing the probe socket is exactly what makes the port
// available to the daemon and to everything else asking the kernel for one at the
// same moment. Every test that wanted a daemon on a free port now lets the kernel
// choose one and reads the answer back ([`start_daemon`]); every test that wants a
// *specific* address holds it for the whole run. Neither guesses.

/// A running daemon: the address it **actually bound**, and its own output
/// streamed while it runs rather than collected after it dies.
///
/// Streaming is what makes the address knowable. The alternative every version
/// of this file used before — take an ephemeral port, release it, hand it to the
/// daemon — cannot hand out a *reserved* port, because releasing the probe socket
/// is precisely what makes the port available to the daemon and to everything
/// else asking the kernel for one at the same moment. Worse, the liveness probe
/// that followed treated "something accepted a connection on this port" as "our
/// child bound this port", so a transient foreign listener satisfied it and the
/// caller was handed an address its own child never bound. Letting the kernel
/// choose (`bind = "127.0.0.1:0"`) and reading the answer back out of the
/// daemon's own `listening` line removes the guess entirely: nobody else can hold
/// a port this daemon has bound.
struct Daemon {
    addr: SocketAddr,
    child: Option<std::process::Child>,
    logs: std::sync::Arc<std::sync::Mutex<String>>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

impl Daemon {
    /// Everything the daemon has written so far.
    fn snapshot(&self) -> String {
        self.logs.lock().unwrap().clone()
    }

    /// Stop it and return everything it wrote, readers joined so the output is
    /// complete rather than whatever had been drained when the kill landed.
    fn stop(&mut self) -> String {
        if let Some(mut child) = self.child.take() {
            child.kill().ok();
            child.wait().ok();
        }
        for reader in self.readers.drain(..) {
            reader.join().ok();
        }
        self.snapshot()
    }
}

/// A test that panics part-way through must not leave a daemon holding a port.
impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Drain one of the child's pipes into the shared buffer, line by line so a
/// chunk boundary cannot split a UTF-8 character out of a path or a message.
fn pump(
    source: impl std::io::Read + Send + 'static,
    sink: std::sync::Arc<std::sync::Mutex<String>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(source).lines() {
            match line {
                Ok(line) => {
                    let mut sink = sink.lock().unwrap();
                    sink.push_str(&line);
                    sink.push('\n');
                }
                Err(_) => break,
            }
        }
    })
}

/// ANSI escape sequences removed. `tracing_subscriber`'s default formatter
/// colours field names even when stdout is a pipe, so the literal `bind=` never
/// appears in the raw stream.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        if chars.next() == Some('[') {
            for c in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    break;
                }
            }
        }
    }
    out
}

/// The address out of the daemon's own `listening` line, which it writes
/// immediately after a successful bind.
fn bound_addr(logs: &str) -> Option<SocketAddr> {
    let plain = strip_ansi(logs);
    let rest = plain.split_once("listening bind=")?.1;
    rest.chars()
        .take_while(|c| !c.is_whitespace())
        .collect::<String>()
        .parse()
        .ok()
}

/// Start a daemon and wait until it reports the address it bound. Panics — with
/// the daemon's own output — if it exits during startup or never gets there.
///
/// `config_body` must ask for an ephemeral port (`bind = "127.0.0.1:0"`); a test
/// that needs a *specific* address is testing something else and should hold the
/// port rather than guess it, the way
/// `a_daemon_binds_exactly_the_address_its_configuration_names` does.
fn start_daemon(config_dir: &Path, config_body: &str) -> Daemon {
    let config = config_dir.join("config.toml");
    std::fs::write(&config, config_body).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nono-cedar-pdp"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let logs = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let readers = vec![
        pump(child.stdout.take().unwrap(), std::sync::Arc::clone(&logs)),
        pump(child.stderr.take().unwrap(), std::sync::Arc::clone(&logs)),
    ];
    let mut daemon = Daemon {
        // Replaced below before the daemon is handed to a caller; a placeholder
        // rather than an `Option` so `Drop` still reaps the child on every panic
        // path in the loop.
        addr: "127.0.0.1:0".parse().unwrap(),
        child: Some(child),
        logs,
        readers,
    };

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let logs = daemon.snapshot();
        match bound_addr(&logs) {
            Some(addr) if addr.port() == 0 => panic!(
                "the daemon reported the address its configuration named rather than the \
                 one it bound, so nothing can reach a daemon told to take a free port: \
                 {logs}"
            ),
            // The log line lands after the bind, so this connect is a formality
            // — but a failure here is a far clearer error than the same failure
            // inside whichever test asked for the daemon.
            Some(addr) if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() => {
                daemon.addr = addr;
                return daemon;
            }
            _ => {}
        }
        if let Some(child) = daemon.child.as_mut() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("the daemon exited during startup ({status}): {logs}");
            }
        }
        if Instant::now() >= deadline {
            panic!("the daemon never reported a bound address: {logs}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `bind = "127.0.0.1:0"` asks the kernel for whatever port is free, and the
/// daemon has to report **the one it got** rather than the placeholder it was
/// configured with. Without that, nothing downstream can reach it, and every
/// test wanting a daemon on a free port is forced to guess an address instead —
/// which is a guess that can be wrong, and was: a released probe port can be
/// taken by anything else on the machine before the daemon binds it.
#[test]
fn a_daemon_told_to_bind_port_zero_reports_the_port_it_bound() {
    let dir = tempfile::tempdir().unwrap();
    let policies = copy_shipped_policies(dir.path());
    let mut daemon = start_daemon(
        dir.path(),
        &format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\nbind = \"127.0.0.1:0\"\n",
            policies.display(),
            dir.path().join("decisions.jsonl").display()
        ),
    );
    let addr = daemon.addr;
    let health = get(addr, "/healthz");
    let logs = daemon.stop();

    assert_ne!(
        addr.port(),
        0,
        "the reported port must be the one the kernel handed out: {logs}"
    );
    assert!(
        health.starts_with("HTTP/1.1 200 OK"),
        "the reported address must be the one that answers: {health:?} (daemon log: {logs})"
    );
}

/// Startup must fail *before* the socket exists: a daemon that binds first and
/// validates second answers requests for the window in between, and nono treats a
/// connection refusal (fail closed) very differently from a 503 or a hang.
///
/// The observable is the `listening` line, which the daemon writes immediately
/// after a successful bind and which now carries the address it actually got —
/// so its absence is exact, and it needs no port of its own. That is why the
/// configuration asks for an ephemeral one: two assertions here used to reach for
/// a *specific* free address (nothing answers on it afterwards; it can still be
/// bound), and both were statements about the state of a global port at an
/// instant this test does not control. Anything else on the machine taking that
/// port turned a passing daemon into a red test. The ordering half — that the
/// load is reported before the bind is even attempted — is
/// `a_policy_load_failure_is_reported_before_the_port_is_touched`, which holds
/// its port for the whole run and so states it without guessing.
#[test]
fn a_policy_load_failure_exits_without_binding_a_port() {
    let policies = policy_dir_with(&[]);
    let dir = tempfile::tempdir().unwrap();

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\nbind = \"127.0.0.1:0\"\n",
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
}

/// The daemon binds **exactly** the address its configuration names, and nothing
/// else. `a_daemon_told_to_bind_port_zero_reports_the_port_it_bound` cannot say
/// this — it reads the address back out of the daemon's own log, so a daemon that
/// ignored `bind` entirely would satisfy it — and every ephemeral-port test now
/// lets the kernel choose, so the guarantee needs its own home.
///
/// Stated by holding the port for the whole run: a daemon that binds the
/// configured address collides and says so, naming it. A daemon that binds
/// anything else does not. No guess about a free port is involved, which is the
/// property that made the previous version of this claim — asserting a daemon
/// answers on a *released* probe address — flake.
#[test]
fn a_daemon_binds_exactly_the_address_its_configuration_names() {
    let dir = tempfile::tempdir().unwrap();
    let policies = copy_shipped_policies(dir.path());
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap();

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\nbind = \"{addr}\"\n",
            policies.display(),
            dir.path().join("decisions.jsonl").display()
        ),
        None,
    );
    assert!(
        !ok,
        "the configured address is held, so the bind must fail: {output}"
    );
    assert!(
        output.to_lowercase().contains("address already in use"),
        "the daemon must have tried the address its configuration named — anything \
         else means `bind` is not what it binds: {output}"
    );
    assert!(
        output.contains(&addr.to_string()),
        "the failure must name the address, or an operator cannot tell which one \
         was taken: {output}"
    );
    drop(occupied);
}

// A test asserting the documented default `127.0.0.1:8181` by occupying it used to live
// here. It was removed as non-hermetic: it depended on the state of a global port at two
// different instants, so if nothing held 8181 when the child started, `serve` bound it
// successfully and the test failed — on a machine where the operator's own daemon is
// running, or not, depending on timing. Deliberately not replaced: the default *value* is
// pinned by `config::tests::loads_minimal_config_with_defaults`, and that the daemon binds
// exactly the address its configuration names is pinned by
// `a_daemon_binds_exactly_the_address_its_configuration_names`, which holds the port
// rather than betting on a free one. Together those cover the guarantee without claiming
// a port a developer may be using.

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
    assert!(
        !output.contains("listening"),
        "the daemon logs `listening` right after a successful bind, so this run bound \
         a port before failing: {output}"
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

/// A certificate and key pair under `dir/tls`, with the key at `mode`. Returns
/// the `[tls]` block naming them.
fn tls_block(dir: &Path, mode: u32) -> String {
    use std::os::unix::fs::PermissionsExt;
    let tls = dir.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let cert = tls.join("cert.pem");
    let key = tls.join("key.pem");
    std::fs::write(&cert, "-----BEGIN CERTIFICATE-----\n").unwrap();
    std::fs::write(&key, "-----BEGIN PRIVATE KEY-----\n").unwrap();
    std::fs::set_permissions(&tls, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
    format!(
        "\n[tls]\ncert = \"{}\"\nkey = \"{}\"\n",
        cert.display(),
        key.display()
    )
}

/// T4 through the binary: a private key another local user can read is a key
/// they can answer nono's approvals with, so the daemon must stop — and stop
/// *before* the socket exists, for the same reason the policy checks do. A
/// refusal that arrives after the bind has already served.
///
/// The ordering is proved the way
/// `a_policy_load_failure_is_reported_before_the_port_is_touched` proves it:
/// hold the port the daemon is told to bind, and require the failure it reports
/// to be the key's rather than `Address already in use`. That is a stronger
/// assertion than "the port is free afterwards", and — the reason it is written
/// this way rather than with `free_loopback_addr` — it needs no *free* ephemeral
/// port, so it does not race the tests that do ask for one. Two more consumers
/// of that helper measurably flaked
/// `a_started_daemon_answers_healthz_and_approve_over_a_real_socket`, whose port
/// the kernel can hand out again between the probe and the daemon's bind.
#[test]
fn a_group_readable_tls_key_refuses_to_start_without_binding() {
    let dir = tempfile::tempdir().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap();
    let block = tls_block(dir.path(), 0o640);

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{POLICY_DIR}\"\naudit_log = \"{}\"\nbind = \"{addr}\"\n{block}",
            dir.path().join("decisions.jsonl").display()
        ),
        None,
    );
    assert!(!ok, "startup must fail: {output}");
    assert!(
        output.contains("private key"),
        "the message must name the subsystem: {output}"
    );
    assert!(
        output.contains(&dir.path().join("tls/key.pem").display().to_string()),
        "the message must name the path: {output}"
    );
    assert!(output.contains("0640"), "the mode must be named: {output}");
    assert!(
        output.contains("chmod 600"),
        "the operator needs the remedy: {output}"
    );
    assert!(
        !output.to_lowercase().contains("address already in use"),
        "the daemon reached the listener before checking who can read its key: {output}"
    );
    assert!(
        !output.contains("listening"),
        "the daemon logs `listening` right after a successful bind, so this run bound \
         a port before failing: {output}"
    );
    drop(occupied);
}

/// T2, and the reason `[tls]` is allowed to fail a startup at all: a daemon that
/// cannot establish the transport its configuration asks for **refuses to serve**.
/// It never falls back to plaintext, because an operator who configured TLS and
/// got a listening daemon has no way to tell the two apart — the worst of the
/// available behaviours, worse than never having had TLS.
///
/// The load-bearing half is not the exit code: with the guard gone the daemon
/// *also* exits non-zero here, because the port it would have bound is held. It
/// is that the daemon is proved never to have reached the bind, which the held
/// port turns into a positive assertion — `Address already in use` is what a
/// fall-through prints, so its absence (with `listening` absent too) is the proof
/// that no socket existed behind the `[tls]` config. The pair is valid: an
/// owner-only `0600` key under a `0700` directory, so the key check passes and
/// the *only* thing left to stop the plaintext listener is the rule under test.
///
/// **Stage 4 must repoint this test, not delete it.** The transitional refusal
/// goes away when the axum-server arm lands and a valid pair starts serving
/// https — so the message assertion moves to task 4.2's client-side one (a
/// plaintext request to a TLS daemon is refused). What must survive the swap is
/// the claim in the name: never plaintext behind `[tls]`. Covered at neither end
/// is how this rule was left unpinned in the first place.
#[test]
fn a_tls_configured_daemon_refuses_rather_than_downgrade_to_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    // Held for the whole run, like `a_group_readable_tls_key_refuses_to_start_
    // without_binding` holds its own: a daemon that fell through to the plaintext
    // listener would collide with it and say so.
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap();
    let block = tls_block(dir.path(), 0o600);

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{POLICY_DIR}\"\naudit_log = \"{}\"\nbind = \"{addr}\"\n{block}",
            dir.path().join("decisions.jsonl").display()
        ),
        None,
    );
    assert!(!ok, "a daemon that cannot serve TLS must not serve: {output}");
    assert!(
        !output.to_lowercase().contains("address already in use"),
        "the daemon fell through to the plaintext listener behind a [tls] config — \
         it reached the bind, which is the silent downgrade T2 forbids: {output}"
    );
    assert!(
        !output.contains("listening"),
        "the daemon logs `listening` right after a successful bind, so this run \
         served plaintext behind a [tls] config: {output}"
    );
    assert!(
        output.contains("[tls]"),
        "the refusal must send the operator to the configuration that caused it: {output}"
    );
    drop(occupied);
}

/// The pair a config names through a symlinked directory, with the key at
/// `mode`. Returns the `[tls]` block written in terms of `link`, the resolved
/// directory the daemon should end up holding, and the symlink path it must not.
fn symlinked_tls_block(dir: &Path, mode: u32) -> (String, std::path::PathBuf, std::path::PathBuf) {
    let actual = dir.join("actual");
    let link = dir.join("link");
    let block = tls_block(&actual, mode);
    std::os::unix::fs::symlink(&actual, &link).unwrap();
    let linked = block.replace(&actual.display().to_string(), &link.display().to_string());
    (linked, actual, link)
}

/// The key check itself runs over the resolved chain: a `0644` key reached
/// through a symlinked directory is still refused, and the refusal names the
/// real file rather than the link the operator typed.
///
/// **This does not pin D7.** It is satisfied by `isolation`'s own `absolutize`,
/// which resolves the path again inside the check — so it stays green with
/// `serve`'s resolution deleted, and that is exactly the two-objects gap D7
/// exists to close. `a_symlinked_tls_pair_is_resolved_before_serving` below is
/// the one that pins the value `serve` holds; keep them apart, because a single
/// test that looks like it covers both is how this was missed the first time.
#[test]
fn a_symlinked_tls_key_is_checked_on_the_chain_it_resolves_to() {
    let dir = tempfile::tempdir().unwrap();
    // Held rather than probed-and-released, for the reason the test above gives.
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap();
    let (linked, actual, _link) = symlinked_tls_block(dir.path(), 0o644);

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{POLICY_DIR}\"\naudit_log = \"{}\"\nbind = \"{addr}\"\n{linked}",
            dir.path().join("decisions.jsonl").display()
        ),
        None,
    );
    assert!(!ok, "startup must fail: {output}");
    assert!(
        output.contains("0644"),
        "the refusal must be the key's mode, read through the link: {output}"
    );
    assert!(
        output.contains(&actual.join("tls/key.pem").display().to_string()),
        "the message must name the resolved path, since that is the one the \
         listener will read: {output}"
    );
    drop(occupied);
}

/// D7 for the TLS pair: `serve` resolves `tls.cert` and `tls.key` **once**, at
/// startup and before the key check, and everything downstream holds only the
/// resolved values. A path resolved twice — once for the check, once for the
/// read — is two different objects, and the gap between them is where a repoint
/// lands.
///
/// Asserted on the values `serve` itself carries, not on a refusal message the
/// check happens to produce: the check re-resolves internally, so a message it
/// wrote proves nothing about `config.tls`. The key is therefore `0600` and
/// *passes*, which leaves the transitional `[tls]` refusal — the one thing
/// downstream of the resolution that prints both paths — as the observable.
///
/// **Stage 4 must repoint this, not delete it.** When the axum-server arm lands,
/// the observable becomes whatever the listener logs or loads; the claim being
/// pinned is unchanged, and it is the claim, not the message, that matters.
#[test]
fn a_symlinked_tls_pair_is_resolved_before_serving() {
    let dir = tempfile::tempdir().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap();
    let (linked, actual, link) = symlinked_tls_block(dir.path(), 0o600);

    let (ok, output) = serve_from(
        dir.path(),
        &format!(
            "policy_dir = \"{POLICY_DIR}\"\naudit_log = \"{}\"\nbind = \"{addr}\"\n{linked}",
            dir.path().join("decisions.jsonl").display()
        ),
        None,
    );
    assert!(!ok, "startup must fail: {output}");
    for what in ["cert.pem", "key.pem"] {
        assert!(
            output.contains(&actual.join("tls").join(what).display().to_string()),
            "serve must hold the resolved {what}, since that is the chain the \
             listener will read: {output}"
        );
    }
    assert!(
        !output.contains(&link.display().to_string()),
        "serve is still holding the configured symlink path, so the chain the key \
         check walked and the chain the listener would read are two objects: {output}"
    );
    drop(occupied);
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
/// proves that `serve` binds anything, or that a decision made over a socket
/// reaches the configured audit log.
///
/// The kernel picks the port rather than the test: `127.0.0.1:8181` is where the
/// README tells an operator to run their own daemon, so claiming it here would
/// fail on a developer's machine — and *guessing* a free one, which is what this
/// test used to do, hands out an address anything else on the machine may take in
/// the window before the daemon binds it. The default value is pinned by
/// `config::tests::loads_minimal_config_with_defaults` and the configured address
/// by `a_daemon_binds_exactly_the_address_its_configuration_names`; neither claim
/// belongs to this test, which is about what happens over the wire once a daemon
/// is up.
#[test]
fn a_started_daemon_answers_healthz_and_approve_over_a_real_socket() {
    let dir = tempfile::tempdir().unwrap();
    let policies = copy_shipped_policies(dir.path());
    let audit_log = dir.path().join("state/decisions.jsonl");
    let mut daemon = start_daemon(
        dir.path(),
        &format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\nbind = \"127.0.0.1:0\"\n\n[agents]\ncedar = \"claude-code\"\n",
            policies.display(),
            audit_log.display()
        ),
    );
    let addr = daemon.addr;
    let health = get(addr, "/healthz");

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

    let logs = daemon.stop();

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
    let records: Vec<serde_json::Value> = trail
        .lines()
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("unparseable audit line {l:?}: {e}"))
        })
        .collect();

    // The real binary's bootstrap load is on the record, ahead of any decision.
    // Only an out-of-process run can show this: the provenance line is written by
    // `main` after the audit log opens, so no in-process router test reaches it.
    let provenance: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| r["kind"] == "policy-set")
        .collect();
    assert_eq!(provenance.len(), 1, "{trail}");
    assert_eq!(provenance[0]["outcome"], "loaded");
    assert_eq!(provenance[0]["generation"], 1);
    assert!(
        provenance[0]["content_hash"]
            .as_str()
            .is_some_and(|h| h.starts_with("sha256:")),
        "the provenance line must name its algorithm: {}",
        provenance[0]
    );
    assert_eq!(
        provenance[0]["at_risk"], false,
        "this fixture's policy dir is not inside the working directory: {}",
        provenance[0]
    );
    assert_eq!(
        records[0]["kind"], "policy-set",
        "the set that decided must be on the record before the decisions it made, \
         or the trail cannot be read forwards: {trail}"
    );

    // The decisions a socket produced must be on the record at the configured path.
    let decisions: Vec<&serde_json::Value> =
        records.iter().filter(|r| r["kind"] == "decision").collect();
    assert_eq!(decisions.len(), 2, "{trail}");
    assert_eq!(decisions[0]["decision"], "allow");
    assert_eq!(
        decisions[0]["matched"],
        serde_json::json!(["10-git:git-read-only"]),
        "{}",
        decisions[0]
    );
    assert_eq!(decisions[1]["decision"], "deny");
}

/// D7: `serve` resolves the configured `policy_dir` once, before the isolation
/// checks, and hands the *resolved* path to the engine, the watcher and every
/// reload re-check — so the chain the checks walked and the chain the loader
/// reads are the same object, and repointing a symlink on the configured path
/// after startup changes nothing the daemon will ever read. `/healthz`
/// reporting the resolved directory is the observable half of that wiring: a
/// daemon reporting the symlink path is a daemon that loaded through a chain
/// the checks never saw.
#[test]
fn a_symlinked_policy_dir_is_resolved_before_serving() {
    let dir = tempfile::tempdir().unwrap();
    let real = copy_shipped_policies(dir.path());
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut daemon = start_daemon(
        dir.path(),
        &format!(
            "policy_dir = \"{}\"\naudit_log = \"{}\"\nbind = \"127.0.0.1:0\"\n",
            link.display(),
            dir.path().join("decisions.jsonl").display()
        ),
    );
    let health = get(daemon.addr, "/healthz");
    daemon.stop();

    assert!(
        !health.is_empty(),
        "the daemon never answered /healthz, so it never got far enough to load"
    );

    // D7's observable used to be `healthz.policy_dir`, which #7 removed as an
    // unauthenticated disclosure of the policy-rewrite target. The `files` array of
    // the provenance line is the replacement, and it is stronger evidence: the old
    // field was the daemon reporting a path *about itself*, which it could get right
    // while loading through a different chain. This is the list of paths the loader
    // actually opened, so a daemon that resolved correctly and one that did not now
    // differ in what they enumerate — which is what D7 is actually about.
    let trail = std::fs::read_to_string(dir.path().join("decisions.jsonl"))
        .unwrap_or_else(|e| panic!("nothing at the configured audit log: {e}"));
    let loaded: serde_json::Value = trail
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["kind"] == "policy-set")
        .unwrap_or_else(|| panic!("no policy-set line in the trail: {trail}"));
    let files: Vec<&str> = loaded["files"]
        .as_array()
        .unwrap_or_else(|| panic!("no files on the provenance line: {loaded}"))
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(!files.is_empty(), "{loaded}");

    let resolved = std::fs::canonicalize(&real).unwrap();
    for file in &files {
        assert!(
            file.starts_with(&resolved.display().to_string()),
            "the daemon must load from the resolved chain, not the configured \
             symlink: {file} is not under {}",
            resolved.display()
        );
        assert!(
            !file.contains("link"),
            "the symlink path is the chain the checks never walked: {file}"
        );
    }
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
