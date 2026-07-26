//! The fail-closed matrix from the spec, exercised over HTTP.
//!
//! One row of it is not here: the zero-policy 503. Reaching that state needs an
//! engine built past the load guards, and that constructor is `#[cfg(test)]` so no
//! production caller can skip them — so the test lives in `src/server.rs`'s unit
//! tests (`a_daemon_with_no_policies_reports_unavailable`).
#![allow(clippy::unwrap_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nono_cedar_pdp::{audit::AuditLog, cedar, config::Config, server, watcher};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// nono sends `args[0]` as an absolute per-run shim path, not the command name.
/// Every request body here uses that shape so the suite cannot green-light a
/// policy pattern that production never matches.
const SHIM_GIT: &str = nono_cedar_pdp::wire::EXAMPLE_SHIM_ARGV0;
const SHIM_CURL: &str =
    "/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/curl";

const POLICY: &str = r#"
@id("allow-git-status")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"launchCommand",
  resource
) when { resource.command == "git" && resource.args.contains("status") };

@id("allow-github-repo-reads")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"httpRequest",
  resource
) when { resource.method == "GET" && resource.path like "/repos/*" };
"#;

fn state(dir: &tempfile::TempDir) -> server::AppState {
    std::fs::write(dir.path().join("p.cedar"), POLICY).unwrap();
    let mut agents = BTreeMap::new();
    agents.insert("cedar".to_string(), "claude-code".to_string());
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        policy_dir: dir.path().to_path_buf(),
        audit_log: dir.path().join("decisions.jsonl"),
        agents,
        tls: None,
    };
    let schema = cedar::schema::load().unwrap();
    let engine = cedar::engine::Engine::bootstrap(schema, config.policy_dir.clone()).unwrap();
    server::AppState {
        engine: Arc::new(engine),
        audit: Arc::new(AuditLog::open(&config.audit_log).unwrap()),
        config: Arc::new(config),
        last_reload: Arc::new(arc_swap::ArcSwapOption::empty()),
    }
}

/// `GET /healthz` on a state the caller has already shaped, so a test can set the
/// last-reload cell before asking.
async fn healthz_of(state: server::AppState) -> (StatusCode, serde_json::Value) {
    let response = server::router(state)
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn post(dir: &tempfile::TempDir, body: &str) -> (StatusCode, serde_json::Value) {
    post_to(&server::router(state(dir)), body).await
}

/// Post to an existing router, so a test can send two requests to *one* daemon
/// — the only way to observe what happens to long-lived state between decisions.
/// Carries the content-type nono's webhook client sends, because every test but the
/// header-gate ones is about what happens to a request that came from nono.
async fn post_to(app: &axum::Router, body: &str) -> (StatusCode, serde_json::Value) {
    post_with_headers(app, &[("content-type", "application/json")], body).await
}

/// Post with *exactly* the headers given and nothing implied, so a test can send what
/// nono's client sends, what a browser would send, or no headers at all.
async fn post_with_headers(
    app: &axum::Router,
    headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder().method("POST").uri("/v1/approve");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn command_body(command: &str, args: &[&str]) -> String {
    command_body_with_request_id("r1", command, args)
}

fn command_body_with_request_id(request_id: &str, command: &str, args: &[&str]) -> String {
    command_body_with_rule(request_id, "rule", command, args)
}

/// A command body whose `intercept_rule` the test chooses: the corpus of real rule
/// shapes needs to vary exactly this field.
fn command_body_with_rule(
    request_id: &str,
    intercept_rule: &str,
    command: &str,
    args: &[&str],
) -> String {
    serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "command",
            "request_id": request_id,
            "command": command,
            "args": args,
            "caller": "session",
            "intercept_rule": intercept_rule,
            "reason": null,
            "child_pid": 42,
            "session_id": "s1"
        }
    })
    .to_string()
}

/// An `endpoint` approval request, as nono's credential proxy sends one: the raw
/// request target, unnormalised and still percent-encoded.
fn endpoint_body(request_id: &str, path: &str) -> String {
    serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "endpoint",
            "request_id": request_id,
            "route_id": "github-api",
            "upstream": "https://api.github.com",
            "method": "GET",
            "path": path,
            "rule_label": "endpoint_policy.approve[GET /repos/*]",
            "reason": "route requires approval",
            "child_pid": 0,
            "session_id": "proxy"
        }
    })
    .to_string()
}

/// A `capability` approval request: a variant the daemon refuses to evaluate,
/// but one that still carries full identifying context on the wire.
fn capability_body(request_id: &str) -> String {
    serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "capability",
            "request_id": request_id,
            "path": "/Users/agent/.ssh/id_ed25519",
            "access": "read",
            "reason": null,
            "child_pid": 7,
            "session_id": "s1"
        }
    })
    .to_string()
}

/// Every audit line, parsed. Panics naming the offending line if any line is not
/// independently parseable JSON.
fn audit_lines(dir: &tempfile::TempDir) -> Vec<serde_json::Value> {
    let path = dir.path().join("decisions.jsonl");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    text.lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("unparseable audit line {line:?}: {e}"))
        })
        .collect()
}

/// One HTTP/1.1 exchange over a real socket, `Connection: close` so the read ends
/// at the response. Synchronous on purpose: the test that uses it runs on a
/// multi-threaded runtime, so `serve` keeps making progress on another worker while
/// this blocks.
fn http(addr: std::net::SocketAddr, request: &str) -> String {
    use std::io::{Read, Write};
    let mut stream =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8_lossy(&response).to_string()
}

/// `server::serve` — the function that actually binds — has no other test caller:
/// every HTTP test here drives the `Router` through `oneshot`, which never creates
/// a socket, never runs `axum::serve`, and would keep passing if the listener were
/// removed entirely.
///
/// An ephemeral port, not the documented default `127.0.0.1:8181`: 8181 is where an
/// operator runs their own daemon, so a test that claimed it would fail on a
/// developer's machine. What matters here is that the address `serve` is handed is
/// the address that answers.
///
/// **The readiness probe has to prove it reached *this* state, not merely that
/// something on the port answered.** Releasing the probe socket is precisely what
/// makes the port available to `serve` — and to everything else asking the kernel
/// for an ephemeral port at that moment — so a bare TCP connect is satisfied by a
/// transient foreign listener while our own bind is still losing the race. The
/// marker is this engine's own bootstrap instant, read out of `/healthz` in
/// process first: nothing else can be reporting it. A lost race is a retry, since
/// it says nothing about the listener under test. `tests/cli.rs` removed the guess
/// entirely by letting the kernel choose the port and reading the answer back out
/// of the daemon's log; in process there is no such channel, so this is the
/// closest sound equivalent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_listener_answers_a_posted_envelope() {
    const ATTEMPTS: u32 = 5;

    let dir = tempfile::tempdir().unwrap();
    let state = state(&dir);
    let (_, own) = healthz_of(state.clone()).await;
    let loaded_at = own["loaded_at"]
        .as_str()
        .unwrap_or_else(|| panic!("no loaded_at to identify this daemon by: {own}"))
        .to_string();

    let mut bound = None;
    for _ in 0..ATTEMPTS {
        // Take an ephemeral port and release it, so `serve` does its own bind.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let serving = {
            let state = state.clone();
            tokio::spawn(async move { server::serve(state, addr).await })
        };

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let ready = loop {
            if serving.is_finished() {
                // The bind lost the race for this port. Nothing to learn from it.
                break false;
            }
            if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200))
                .is_ok()
            {
                let health = tokio::task::spawn_blocking(move || {
                    http(
                        addr,
                        &format!(
                            "GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
                        ),
                    )
                })
                .await
                .unwrap();
                break health.contains(&loaded_at);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "serve never accepted a connection on {addr}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        if ready {
            bound = Some((addr, serving));
            break;
        }
        serving.abort();
    }
    let (addr, serving) = bound.unwrap_or_else(|| {
        panic!("no ephemeral port survived {ATTEMPTS} attempts between the probe and the bind")
    });

    let body = command_body("git", &[SHIM_GIT, "status"]);
    let response = tokio::task::spawn_blocking(move || {
        let health = http(
            addr,
            &format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        );
        let approve = http(
            addr,
            &format!(
                "POST /v1/approve HTTP/1.1\r\nHost: {addr}\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        (health, approve)
    })
    .await
    .unwrap();
    let (health, approve) = response;

    serving.abort();

    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health:?}");
    assert!(health.contains("\"generation\":1"), "{health:?}");
    assert!(approve.starts_with("HTTP/1.1 200 OK"), "{approve:?}");
    assert!(
        approve.ends_with("{\"decision\":\"allow\"}"),
        "the decision must survive the real wire, not just the Router: {approve:?}"
    );

    // And the decision a socket produced is on the record.
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0]["decision"], "allow");
}

/// The `User-Agent` nono 0.69.0's webhook client sends
/// (`crates/nono-cli/src/approval_runtime.rs`: `nono-cli/{CARGO_PKG_VERSION}`). Not a
/// credential and never treated as one — it is recorded as evidence only.
const NONO_USER_AGENT: &str = "nono-cli/0.69.0";

/// Exactly the two headers nono's webhook client sends, and nothing else.
const NONO_HEADERS: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("user-agent", NONO_USER_AGENT),
];

/// A POST with no `Content-Type` cannot have come from nono's client, which always
/// sends one. Two halves matter equally: the 415, and that **no audit line is
/// written** — recording a refusal would recreate the injection this closes, just
/// with a different label on it. The refusal must also not be decision-shaped: nono
/// did not ask, so there is no `decision` key for anything to record.
#[tokio::test]
async fn a_request_with_no_content_type_is_refused_with_415_and_never_audited() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let body = command_body("git", &[SHIM_GIT, "status"]);

    let (status, response, logs) = {
        let capture = capture();
        let (status, response) = post_with_headers(&app, &[], &body).await;
        (status, response, capture.text())
    };

    assert_eq!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "a request with no content-type must be refused: {response}"
    );
    assert!(
        response["decision"].is_null(),
        "a refusal is not a decision: nono did not ask, so nothing is owed a deny \
         reason it could record: {response}"
    );
    assert!(
        audit_lines(&dir).is_empty(),
        "a refused request must leave no audit line at all — writing one is the \
         injection this closes, relabelled: {:#?}",
        audit_lines(&dir)
    );
    assert!(
        logs.contains("WARN"),
        "an operator must see the endpoint being probed: {logs:?}"
    );
    assert!(
        logs.contains("content_type=-"),
        "the WARN must name the observed content-type, absent ones included: {logs:?}"
    );
}

/// The three content types a CORS-*simple* cross-origin POST may carry — the only
/// ones a page the operator merely visited can send without a preflight. Refusing
/// them is what closes the one vector that does not already require local code
/// execution, so each is pinned individually rather than trusted to a single case.
#[tokio::test]
async fn every_cors_simple_content_type_is_refused_with_415_and_never_audited() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let body = command_body("git", &[SHIM_GIT, "status"]);

    for content_type in [
        "text/plain",
        "text/plain;charset=UTF-8",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    ] {
        let (status, response, logs) = {
            let capture = capture();
            let (status, response) =
                post_with_headers(&app, &[("content-type", content_type)], &body).await;
            (status, response, capture.text())
        };
        assert_eq!(
            status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type} is a CORS-simple content type; accepting it reopens the \
             drive-by vector: {response}"
        );
        assert!(response["decision"].is_null(), "{response}");
        assert!(
            logs.contains(&format!("content_type={content_type}")),
            "the WARN must name what was observed: {logs:?}"
        );
    }

    assert!(
        audit_lines(&dir).is_empty(),
        "none of the refusals may leave an audit line: {:#?}",
        audit_lines(&dir)
    );
}

/// The tolerance half of the same control: a client may legitimately add a charset,
/// and RFC 9110 makes the media type case-insensitive. Getting either wrong refuses
/// every real request while every "is it refused?" test stays green — which is why
/// this asserts a full decision, not merely a non-415.
#[tokio::test]
async fn a_json_content_type_with_parameters_or_odd_case_is_decided_normally() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));

    for content_type in [
        "application/json",
        "application/json; charset=utf-8",
        "application/json;charset=utf-8",
        "APPLICATION/JSON",
        "Application/JSON; charset=UTF-8",
    ] {
        let (status, response) = post_with_headers(
            &app,
            &[("content-type", content_type)],
            &command_body("git", &[SHIM_GIT, "status"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{content_type}: {response}");
        assert_eq!(
            response,
            serde_json::json!({"decision": "allow"}),
            "{content_type} names the JSON media type, so the request must be \
             decided on its merits: {response}"
        );
    }

    assert_eq!(
        audit_lines(&dir).len(),
        5,
        "every accepted request is a decision, so every one is on the record: {:#?}",
        audit_lines(&dir)
    );
}

/// nono never sends `Origin`; a browser-issued cross-origin request always does. The
/// check is deliberately independent of the content-type one (design D2), so neither
/// is load-bearing alone: this request carries exactly the content-type nono sends
/// and must still be refused.
#[tokio::test]
async fn a_request_carrying_an_origin_is_refused_with_403_even_with_a_json_content_type() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let body = command_body("git", &[SHIM_GIT, "status"]);

    let (status, response, logs) = {
        let capture = capture();
        let (status, response) = post_with_headers(
            &app,
            &[
                ("content-type", "application/json"),
                ("origin", "https://evil.example"),
            ],
            &body,
        )
        .await;
        (status, response, capture.text())
    };

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a correct content-type must not excuse an Origin: {response}"
    );
    assert!(response["decision"].is_null(), "{response}");
    assert!(
        audit_lines(&dir).is_empty(),
        "a refused request must leave no audit line: {:#?}",
        audit_lines(&dir)
    );
    assert!(
        logs.contains("origin=https://evil.example"),
        "the WARN must name the observed Origin: {logs:?}"
    );
}

/// The gate must not change a single decision (design non-goal). A request shaped
/// exactly as nono's client sends one — the JSON content-type, the `nono-cli/<version>`
/// User-Agent, no `Origin` — gets the same allow and the same deny as before, with the
/// same audit lines.
#[tokio::test]
async fn a_nono_shaped_request_is_decided_exactly_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));

    let (status, allowed) = post_with_headers(
        &app,
        NONO_HEADERS,
        &command_body("git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(allowed, serde_json::json!({"decision": "allow"}));

    let (status, denied) = post_with_headers(
        &app,
        NONO_HEADERS,
        &command_body("curl", &[SHIM_CURL, "evil.example"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(denied["decision"], "deny", "{denied}");
    assert!(
        denied["reason"].as_str().unwrap().contains("no policy"),
        "{denied}"
    );

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 2, "{lines:#?}");
    assert_eq!(lines[0]["decision"], "allow");
    assert_eq!(lines[1]["decision"], "deny");
}

/// The fail-closed contract sits *behind* the gate and is untouched by it: a request
/// whose headers are nono's but whose body is unusable is still a `200` carrying our
/// own deny reason (nono records the reason; for any non-2xx it records only the
/// status), and still one audit line. The gate's 4xx is the third case — "this was
/// not a request" — not a widening of the 4xx surface.
#[tokio::test]
async fn a_malformed_body_that_passes_the_gate_is_still_a_200_deny_on_the_record() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));

    let (status, response) = post_with_headers(&app, NONO_HEADERS, "{not json").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a 4xx also denies but loses our reason in nono's audit trail: {response}"
    );
    assert_eq!(response["decision"], "deny", "{response}");
    assert!(
        response["reason"].as_str().unwrap().contains("malformed"),
        "{response}"
    );

    let lines = audit_lines(&dir);
    assert_eq!(
        lines.len(),
        1,
        "a decision returned to the caller is always on the record: {lines:#?}"
    );
    assert_eq!(lines[0]["decision"], "deny");
}

/// The `User-Agent` is recorded as **evidence, not verification**: browser
/// JavaScript cannot set the header at all, so an absent or odd value is a real
/// signal, while a local process sets it to anything it likes, so a value that looks
/// right proves nothing. Both halves are why it is recorded verbatim and trusted for
/// nothing — and why an absent one is an explicit `null` rather than a missing key: a
/// consumer must be able to tell "presented nothing" from "we stopped recording it".
#[tokio::test]
async fn a_decided_line_records_the_user_agent_as_sent_and_null_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));

    let (status, _) = post_with_headers(
        &app,
        NONO_HEADERS,
        &command_body_with_request_id("with-agent", "git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = post_with_headers(
        &app,
        &[("content-type", "application/json")],
        &command_body_with_request_id("no-agent", "git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 2, "{lines:#?}");
    assert_eq!(
        lines[0]["user_agent"], NONO_USER_AGENT,
        "the line must record what the caller presented, verbatim: {:#?}",
        lines[0]
    );
    assert!(
        lines[1].as_object().unwrap().contains_key("user_agent"),
        "a request with no User-Agent must record an explicit null, not omit the \
         key — the key set is identical on every line: {:#?}",
        lines[1]
    );
    assert!(lines[1]["user_agent"].is_null(), "{:#?}", lines[1]);
}

/// A rejected request never becomes a `PolicyQuery`, and its line must still carry the
/// key — with the observed agent when the request presented one. The rejected path is
/// the one a hostile caller controls, so it is the one where the evidence matters most.
#[tokio::test]
async fn a_rejected_line_records_the_user_agent_too() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));

    let (status, response) = post_with_headers(&app, NONO_HEADERS, &capability_body("cap-1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["decision"], "deny", "{response}");

    let (status, response) = post_with_headers(&app, NONO_HEADERS, "{not json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["decision"], "deny", "{response}");

    // And one with nothing to record, so the null is asserted on this path too.
    let (status, _) =
        post_with_headers(&app, &[("content-type", "application/json")], "{not json").await;
    assert_eq!(status, StatusCode::OK);

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 3, "{lines:#?}");
    assert_eq!(
        lines[0]["user_agent"], NONO_USER_AGENT,
        "an unsupported variant is still a decision, with the same evidence on it: {:#?}",
        lines[0]
    );
    assert_eq!(
        lines[1]["user_agent"], NONO_USER_AGENT,
        "a body that never parsed still presented a User-Agent: {:#?}",
        lines[1]
    );
    assert!(
        lines[2].as_object().unwrap().contains_key("user_agent")
            && lines[2]["user_agent"].is_null(),
        "{:#?}",
        lines[2]
    );
}

/// The same boundary rule the other request-derived fields follow, end to end: a
/// `User-Agent` carrying a C1 control must not reach the audit file raw. C1
/// specifically because serde's JSON encoding escapes only C0 (U+0000..U+001F), so a
/// C0-based test would pass with no escaping at all — and because hyper accepts
/// `0xC2 0x9B` (CSI) in a header value, so this is reachable over a real socket, not
/// merely at the recording boundary. DEL is unreachable through a header (the HTTP
/// parsers reject 0x7F), so it is pinned in `audit.rs`'s unit tests instead.
#[tokio::test]
async fn a_c1_control_in_the_user_agent_never_reaches_the_audit_file_raw() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));

    let (status, _) = post_with_headers(
        &app,
        &[
            ("content-type", "application/json"),
            ("user-agent", "nono-cli/0.69.0\u{9b}31mDENY OVERRIDDEN"),
        ],
        &command_body("git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let raw = std::fs::read(dir.path().join("decisions.jsonl")).unwrap();
    let csi = "\u{9b}".as_bytes(); // 0xC2 0x9B in UTF-8
    assert!(
        !raw.windows(csi.len()).any(|window| window == csi),
        "a raw CSI byte reached the audit file: {:?}",
        String::from_utf8_lossy(&raw)
    );
    let lines = audit_lines(&dir);
    assert_eq!(
        lines[0]["user_agent"], "nono-cli/0.69.0\\u{009b}31mDENY OVERRIDDEN",
        "escaped, not truncated or dropped — the evidence has to survive: {:#?}",
        lines[0]
    );
}

#[tokio::test]
async fn permitted_command_gets_allow() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &command_body("git", &[SHIM_GIT, "status"])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"decision": "allow"}));
}

#[tokio::test]
async fn unpermitted_command_gets_deny_with_reason() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &command_body("curl", &[SHIM_CURL, "evil.example"])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");
    assert!(body["reason"].as_str().unwrap().contains("no policy"));
}

/// The endpoint half of the wrong-allow matrix: a permit written the way the design
/// and the README write it (`path like "/repos/*"`) must not be satisfiable by a
/// traversal, and the deny nono records has to say *why*.
#[tokio::test]
async fn a_traversal_endpoint_path_gets_200_deny_naming_the_ambiguity() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &endpoint_body("p1", "/repos/../user/keys")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny", "{body}");
    let reason = body["reason"].as_str().unwrap();
    assert!(reason.contains("ambiguous endpoint path"), "{reason}");
    assert!(reason.contains("/repos/../user/keys"), "{reason}");

    // The same permit still decides an unambiguous path, so the guard has not simply
    // turned every endpoint approval into a deny.
    let (status, body) = post(&dir, &endpoint_body("p2", "/repos/foo/bar")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"decision": "allow"}), "{body}");
}

/// A refused path is still a decision nono acts on, so it is on the record with the
/// path as sent — the audit trail is where an operator sees what was attempted.
#[tokio::test]
async fn an_ambiguous_endpoint_path_is_audited_with_the_raw_path() {
    let dir = tempfile::tempdir().unwrap();
    post(&dir, &endpoint_body("p1", "/repos/%2e%2e/user/keys")).await;
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["decision"], "deny");
    assert_eq!(lines[0]["matched"], serde_json::json!([]));
    assert!(
        lines[0]["resource"]
            .as_str()
            .unwrap()
            .contains("/repos/%2e%2e/user/keys"),
        "{}",
        lines[0]
    );
    assert!(
        lines[0]["reason"]
            .as_str()
            .unwrap()
            .contains("ambiguous endpoint path"),
        "{}",
        lines[0]
    );
}

#[tokio::test]
async fn malformed_body_gets_200_deny_not_4xx() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, "{not json").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a 4xx also denies but loses our reason in nono's audit trail"
    );
    assert_eq!(body["decision"], "deny");
    assert!(body["reason"].as_str().unwrap().contains("malformed"));
}

#[tokio::test]
async fn unsupported_variant_gets_200_deny() {
    let dir = tempfile::tempdir().unwrap();
    let body = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "capability",
            "request_id": "c1",
            "path": "/etc/passwd",
            "access": "read",
            "reason": null,
            "child_pid": 7,
            "session_id": "s1"
        }
    })
    .to_string();
    let (status, body) = post(&dir, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");
    assert!(body["reason"].as_str().unwrap().contains("unsupported"));
}

#[tokio::test]
async fn every_decision_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let _ = post(&dir, &command_body("git", &[SHIM_GIT, "status"])).await;
    let text = std::fs::read_to_string(dir.path().join("decisions.jsonl")).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains("\"decision\":\"allow\""));
}

/// "Which rule decided it" is the question the audit trail exists to answer, and
/// `eval_us` is the other half of the same line. Both are absent from every other
/// audit assertion in this repo: the unit test feeds a synthetic `Decision::deny`,
/// whose `matched` is empty and `eval_us` zero by construction, and the rejection
/// tests only ever see an empty `matched`. Dropping `matched` from `AuditRecord`
/// entirely would leave every one of those green.
#[tokio::test]
async fn the_audit_line_names_the_rule_that_decided_and_the_evaluation_time() {
    let dir = tempfile::tempdir().unwrap();
    let (_, body) = post(
        &dir,
        &command_body_with_request_id("decided", "git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(body, serde_json::json!({"decision": "allow"}));

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let line = &lines[0];
    assert_eq!(line["request_id"], "decided");
    assert_eq!(line["decision"], "allow");
    assert_eq!(
        line["matched"],
        serde_json::json!(["p:allow-git-status"]),
        "the line must name the policy that permitted it: {line:#?}"
    );
    assert!(
        line["reason"]
            .as_str()
            .unwrap()
            .contains("p:allow-git-status"),
        "{line:#?}"
    );
    assert!(
        line["eval_us"].as_u64().is_some_and(|us| us > 0),
        "a real evaluation takes measurable time: {line:#?}"
    );
    assert_eq!(line["action"], "launchCommand");
    assert_eq!(line["principal"], "Nono::Caller::\"session\"");

    // A default deny is the other shape of the same field: nothing matched, so the
    // list is empty rather than missing, and the reason says why.
    let (_, body) = post(
        &dir,
        &command_body_with_request_id("undecided", "curl", &[SHIM_CURL, "evil.example"]),
    )
    .await;
    assert_eq!(body["decision"], "deny");
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 2, "{lines:#?}");
    assert_eq!(
        lines[1]["matched"],
        serde_json::json!([]),
        "{:#?}",
        lines[1]
    );
    assert!(
        lines[1]["eval_us"].as_u64().is_some_and(|us| us > 0),
        "{:#?}",
        lines[1]
    );
}

/// Every `intercept_rule` shape real nono sends, driven through the full path —
/// HTTP parse → evaluate → audit — asserting the value reaches the audit line
/// byte-identically. The shapes are verified upstream facts, not guesses: in
/// nolabs-ai/nono `crates/nono-cli/src/tool-sandbox/policy.rs`,
/// `ResolvedInterceptAction::rule_label()` returns the matched rule's args joined
/// with spaces (upstream's own test asserts `"push --force"`), `"<catch-all>"` for
/// an empty-args rule, and `evaluate_invocation_policy` produces the labels
/// `invocation_policy.approve[<index>]` and `invocation_policy.default`. A corpus
/// that only ever sends single tokens cannot catch a consumer that assumes one
/// word.
#[tokio::test]
async fn every_real_intercept_rule_shape_survives_to_the_audit_line() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let shapes = [
        "status",                       // one rule arg
        "push --force",                 // args joined with spaces
        "<catch-all>",                  // the label of an empty-args rule
        "invocation_policy.approve[0]", // invocation-policy approve label
        "invocation_policy.default",    // invocation-policy default label
    ];
    for (index, rule) in shapes.iter().enumerate() {
        let (status, _) = post_to(
            &app,
            &command_body_with_rule(&format!("rule-{index}"), rule, "git", &[SHIM_GIT, "status"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{rule}");
    }

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), shapes.len(), "{lines:#?}");
    for (line, rule) in lines.iter().zip(shapes) {
        assert_eq!(
            line["intercept_rule"],
            serde_json::json!(rule),
            "the rule that routed the request must survive to the audit line \
             byte-identically: {line:#?}"
        );
        assert_eq!(line["child_pid"], 42, "{line:#?}");
        assert!(
            line.as_object().unwrap().contains_key("rule_label") && line["rule_label"].is_null(),
            "a command line carries rule_label as an explicit null: {line:#?}"
        );
    }
}

/// The endpoint half of the wire had no end-to-end coverage at all: the adapter and
/// the engine each had a unit test, but nothing posted an `endpoint` envelope to
/// `/v1/approve` and looked at what was recorded. `httpRequest` is the whole L7
/// surface — the credential proxy's decisions — so a break anywhere between the
/// router and the audit line would have gone unnoticed.
#[tokio::test]
async fn an_endpoint_envelope_is_decided_and_audited_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &endpoint_body("proxy-1", "/repos/foo/bar")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"decision": "allow"}), "{body}");

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let line = &lines[0];
    assert_eq!(line["request_id"], "proxy-1");
    assert_eq!(line["action"], "httpRequest");
    assert_eq!(line["decision"], "allow");
    assert_eq!(
        line["matched"],
        serde_json::json!(["p:allow-github-repo-reads"]),
        "{line:#?}"
    );
    // nono sends no session identity for an endpoint request, so the daemon pins
    // the proxy identity itself — and the audit line has to show that, not a
    // borrowed session.
    assert_eq!(line["session_id"], "proxy");
    assert_eq!(line["principal"], "Nono::Caller::\"proxy\"");
    assert_eq!(line["backend"], "cedar");
    assert_eq!(line["agent"], "claude-code");
    assert_eq!(
        line["resource"], "GET https://api.github.com/repos/foo/bar",
        "the line must say what was asked: {line:#?}"
    );
    assert!(
        line["eval_us"].as_u64().is_some_and(|us| us > 0),
        "{line:#?}"
    );
    // What routed the request here: the route rule label exactly as sent, the pid
    // exactly as the wire carried it (this body sends the 0 real nono hardcodes
    // for its proxy), and an explicitly null intercept_rule — the key set is
    // identical on every line kind.
    assert_eq!(
        line["rule_label"], "endpoint_policy.approve[GET /repos/*]",
        "the label must survive as sent: {line:#?}"
    );
    assert_eq!(line["child_pid"], 0, "{line:#?}");
    assert!(
        line.as_object().unwrap().contains_key("intercept_rule")
            && line["intercept_rule"].is_null(),
        "an endpoint line carries intercept_rule as an explicit null: {line:#?}"
    );

    // A method the permit does not cover is denied, so the permit is not a
    // blanket endpoint allow.
    let denied = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "endpoint",
            "request_id": "proxy-2",
            "route_id": "github-api",
            "upstream": "https://api.github.com",
            "method": "DELETE",
            "path": "/repos/foo/bar",
            "rule_label": "endpoint_policy.approve[DELETE /repos/*]",
            "reason": "route requires approval",
            "child_pid": 0,
            "session_id": "proxy"
        }
    })
    .to_string();
    let (status, body) = post(&dir, &denied).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny", "{body}");
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 2, "{lines:#?}");
    assert_eq!(lines[1]["action"], "httpRequest");
    assert_eq!(lines[1]["decision"], "deny");
    assert_eq!(
        lines[1]["matched"],
        serde_json::json!([]),
        "{:#?}",
        lines[1]
    );
}

/// Fidelity, not paraphrase: real nono hardcodes `child_pid: 0` for its proxy's
/// endpoint requests, but the audit line records what the wire actually carried.
/// The first implementation pinned `Some(0)` for endpoints, which *rewrote* the
/// claim rather than recording it — a sender asserting a pid must leave that
/// assertion on the record, where an investigator can see it (and see that it is
/// not what real nono sends).
#[tokio::test]
async fn an_endpoint_child_pid_is_recorded_as_sent_not_rewritten_to_zero() {
    let dir = tempfile::tempdir().unwrap();
    let body = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "endpoint",
            "request_id": "claimed-pid",
            "route_id": "github-api",
            "upstream": "https://api.github.com",
            "method": "GET",
            "path": "/repos/foo/bar",
            "rule_label": "endpoint_policy.approve[GET /repos/*]",
            "reason": "route requires approval",
            "child_pid": 7,
            "session_id": "proxy"
        }
    })
    .to_string();

    let (status, _) = post(&dir, &body).await;
    assert_eq!(status, StatusCode::OK);

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(
        lines[0]["child_pid"], 7,
        "the wire claimed pid 7, so the line must record 7 — recording the claim, \
         not rewriting it to the 0 real nono would have sent: {:#?}",
        lines[0]
    );
}

/// Rotation happens to a *running* daemon: `logrotate` or an operator renames the
/// log while the process holds it open. Writes to the renamed inode keep
/// succeeding, so nothing errors — every later decision is answered and recorded
/// nowhere an operator can read, while `/healthz` stays green. One daemon, two
/// requests, a rename in between.
#[tokio::test]
async fn decisions_after_a_log_rotation_still_land_at_the_configured_path() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let path = dir.path().join("decisions.jsonl");
    let rotated = dir.path().join("decisions.jsonl.1");

    let (status, body) = post_to(
        &app,
        &command_body_with_request_id("before-rotation", "git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "allow");

    std::fs::rename(&path, &rotated).unwrap();

    let (status, body) = post_to(
        &app,
        &command_body_with_request_id("after-rotation", "git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an audit failure never changes a decision"
    );
    assert_eq!(body["decision"], "allow");

    let lines = audit_lines(&dir);
    assert_eq!(
        lines.len(),
        1,
        "the reopened log holds exactly the decision made after the rotation: {lines:#?}"
    );
    assert_eq!(lines[0]["request_id"], "after-rotation");

    let archived = std::fs::read_to_string(&rotated).unwrap();
    assert!(archived.contains("before-rotation"), "{archived:?}");
    assert!(
        !archived.contains("after-rotation"),
        "nothing may be appended to the detached inode: {archived:?}"
    );
}

/// An oversized body must be refused the same way every other unusable input is:
/// HTTP 200 with our own reason. Upstream maps any non-2xx to
/// `"approval webhook … returned HTTP {status}"`, which is exactly the generic
/// status outcome the contract exists to avoid — and axum's default extractor
/// limit produces a plain-text 413 with no audit line at all.
#[tokio::test]
async fn an_oversized_body_gets_200_deny_and_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let padding = "a".repeat(server::MAX_REQUEST_BYTES);
    let body = serde_json::json!({
        "backend": "cedar",
        "padding": padding,
        "request": {
            "capability_type": "command",
            "request_id": "r1",
            "command": "git",
            "args": [SHIM_GIT, "status"],
            "caller": "session",
            "intercept_rule": "rule",
            "reason": null,
            "child_pid": 42,
            "session_id": "s1"
        }
    })
    .to_string();
    assert!(body.len() > server::MAX_REQUEST_BYTES);

    let (status, body) = post(&dir, &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a 413 denies too, but nono then records only the HTTP status"
    );
    assert_eq!(body["decision"], "deny");
    assert!(
        body["reason"].as_str().unwrap().contains("limit"),
        "{body:#?}"
    );

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0]["decision"], "deny");
}

/// The cap is generous on purpose: a long argv must never be mistaken for an
/// attack, so a body well inside the limit is still decided on its merits.
#[tokio::test]
async fn a_large_but_permitted_body_is_still_decided() {
    let dir = tempfile::tempdir().unwrap();
    let long_arg = "a".repeat(server::MAX_REQUEST_BYTES / 2);
    let body = command_body("git", &[SHIM_GIT, "status", &long_arg]);
    assert!(body.len() < server::MAX_REQUEST_BYTES);
    let (status, body) = post(&dir, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "allow");
}

/// A denial the caller receives but that leaves no audit line is a decision with
/// no reviewable record. The rejection paths — unsupported variant, malformed
/// body, oversized body — are exactly the ones a hostile caller controls.
#[tokio::test]
async fn rejected_requests_are_audited_too() {
    let dir = tempfile::tempdir().unwrap();

    let (_, allowed) = post(&dir, &command_body("git", &[SHIM_GIT, "status"])).await;
    let (_, policy_denied) = post(&dir, &command_body("curl", &[SHIM_CURL, "evil.example"])).await;
    let (_, unsupported) = post(&dir, &capability_body("cap-1")).await;
    let (_, malformed) = post(&dir, "{").await;

    assert_eq!(allowed["decision"], "allow");
    assert_eq!(policy_denied["decision"], "deny");
    assert_eq!(unsupported["decision"], "deny");
    assert_eq!(malformed["decision"], "deny");

    let lines = audit_lines(&dir);
    assert_eq!(
        lines.len(),
        4,
        "4 decisions were returned to the caller, so 4 audit lines must exist: {lines:#?}"
    );
    let decisions: Vec<&str> = lines
        .iter()
        .map(|l| l["decision"].as_str().unwrap())
        .collect();
    assert_eq!(decisions, vec!["allow", "deny", "deny", "deny"]);
}

/// The wire context of a rejected request is what makes its audit line
/// reviewable: a `capability` request carries `request_id`, `session_id` and the
/// backend even though the daemon refuses to evaluate it.
#[tokio::test]
async fn an_unsupported_variant_is_audited_with_its_wire_context() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &capability_body("cap-1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let line = &lines[0];
    assert_eq!(line["request_id"], "cap-1");
    assert_eq!(line["session_id"], "s1");
    assert_eq!(line["backend"], "cedar");
    assert_eq!(line["agent"], "claude-code");
    assert_eq!(line["decision"], "deny");
    assert!(
        line["reason"].as_str().unwrap().contains("unsupported"),
        "{line:#?}"
    );
    assert!(
        line["ts"].as_str().unwrap().contains('T'),
        "want an RFC 3339 timestamp: {line:#?}"
    );
    assert!(
        line["resource"]
            .as_str()
            .unwrap_or_default()
            .contains("capability"),
        "the refused variant is the only 'what was asked' we have: {line:#?}"
    );
}

/// A body that is not JSON at all yields no context — but the denial still has to
/// be on the record, with the fields it cannot fill left explicitly null.
#[tokio::test]
async fn a_malformed_body_is_audited_without_context() {
    let dir = tempfile::tempdir().unwrap();
    let (_, body) = post(&dir, "{not json").await;
    assert_eq!(body["decision"], "deny");

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0]["decision"], "deny");
    assert!(lines[0]["request_id"].is_null(), "{:#?}", lines[0]);
    assert!(
        lines[0]["reason"].as_str().unwrap().contains("malformed"),
        "{:#?}",
        lines[0]
    );
    // The fixed key set holds on the rejection path too: nothing routed a request
    // that never parsed, so all three routing keys are explicit nulls, not absent.
    for key in ["child_pid", "intercept_rule", "rule_label"] {
        assert!(
            lines[0].as_object().unwrap().contains_key(key),
            "a rejected line must carry {key} as an explicit null: {:#?}",
            lines[0]
        );
        assert!(lines[0][key].is_null(), "{key}: {:#?}", lines[0]);
    }
}

/// stdout and the audit log carry the same request-derived content and nothing like
/// the same protection: the log is `0600`, tightened if it was looser and reattached
/// across rotation, while stdout goes wherever the operator redirected it — a shared
/// journal, a log aggregator, terminal scrollback. So the *identifiers and outcome*
/// belong at INFO and the attempted command line does not.
///
/// The distinctive argument is what makes this assertion real: `git` also appears in
/// the matched policy id, so asserting the absence of the command *name* would be
/// unfalsifiable. The shim path is asserted absent too, since it is the other half of
/// what `resource_summary` would have leaked.
#[tokio::test]
async fn the_default_decision_line_carries_identifiers_but_not_the_command_line() {
    let dir = tempfile::tempdir().unwrap();
    let secret_argument = "--author=leaked-into-an-unprotected-stream";
    let body =
        command_body_with_request_id("telemetry-1", "git", &[SHIM_GIT, "status", secret_argument]);

    let logs = {
        let capture = capture();
        let (status, response) = post(&dir, &body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        capture.text()
    };

    // The identifiers and the outcome: enough to correlate with the audit line and
    // to watch the daemon work.
    for field in [
        "request_id=telemetry-1",
        "session_id=s1",
        "backend=cedar",
        "action=\"launchCommand\"",
        "allow=true",
        "matched=",
        "eval_us=",
    ] {
        assert!(
            logs.contains(field),
            "the INFO decision line must carry {field:?}: {logs:?}"
        );
    }

    assert!(
        !logs.contains(secret_argument),
        "the attempted command line must not reach stdout at the default level — \
         stdout has none of the audit log's permissions: {logs:?}"
    );
    assert!(
        !logs.contains(SHIM_GIT),
        "the argv must not reach stdout at the default level either: {logs:?}"
    );
}

/// Relocated, not deleted (design D6): the resource summary is the first thing you
/// want when a policy will not match, so DEBUG keeps it — as a *separate* event,
/// because `tracing` fields are fixed per event. It must repeat `request_id` or it
/// cannot be joined to the INFO line it belongs to, and it must stay control-escaped:
/// the command line is chosen by whatever the agent ran.
#[tokio::test]
async fn at_debug_the_resource_summary_is_emitted_and_can_be_joined_by_request_id() {
    let dir = tempfile::tempdir().unwrap();
    let hostile_argument = "commit\u{1b}[2K\rINFO forged allow=true";
    let body = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "command",
            "request_id": "telemetry-2",
            "command": "git",
            "args": [SHIM_GIT, "status", hostile_argument],
            "caller": "session",
            "intercept_rule": "status",
            "reason": null,
            "child_pid": 42,
            "session_id": "s1"
        }
    })
    .to_string();

    let logs = {
        let capture = capture_at(tracing::Level::DEBUG);
        let (status, response) = post(&dir, &body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        capture.text()
    };

    assert!(
        logs.contains("DEBUG"),
        "the detail must be emitted when the operator opts in: {logs:?}"
    );
    assert!(
        logs.contains(SHIM_GIT),
        "the resource summary is what DEBUG exists to provide: {logs:?}"
    );
    // Two events, so the identifier has to appear on the DEBUG one as well — count
    // it rather than merely finding it, or a single INFO line would satisfy this.
    assert!(
        logs.matches("request_id=telemetry-2").count() >= 2,
        "the DEBUG event must repeat request_id or it cannot be joined to the \
         decision line: {logs:?}"
    );
    assert!(
        !logs.contains('\u{1b}'),
        "raw ESC reached the operator log: {logs:?}"
    );
    assert!(
        logs.contains("\\u{001b}"),
        "the escape must be visible, not dropped: {logs:?}"
    );
}

/// Nothing is *lost* by the split, only relocated: the audit log is the complete
/// record at any log level, so the detail removed from stdout is still recorded in
/// the file that has permissions.
#[tokio::test]
async fn the_audit_line_keeps_the_full_resource_summary_at_the_default_level() {
    let dir = tempfile::tempdir().unwrap();
    let secret_argument = "--author=only-in-the-audit-log";
    let body =
        command_body_with_request_id("telemetry-3", "git", &[SHIM_GIT, "status", secret_argument]);

    let logs = {
        let capture = capture();
        let (status, _) = post(&dir, &body).await;
        assert_eq!(status, StatusCode::OK);
        capture.text()
    };
    assert!(!logs.contains(secret_argument), "{logs:?}");

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let resource = lines[0]["resource"].as_str().unwrap();
    assert!(
        resource.contains(secret_argument) && resource.contains(SHIM_GIT),
        "the audit line must still carry the complete resource summary: {:#?}",
        lines[0]
    );
}

/// The command variant above is only half the surface: nono's credential proxy
/// forwards the request target verbatim, query string included, and for an API proxy
/// the query string is where a token lands. So an `endpoint` decision has to hold the
/// same line at the default level — identifiers and outcome, no request target.
#[tokio::test]
async fn the_default_decision_line_carries_identifiers_but_not_the_endpoint_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = "/repos/foo/bar?token=endpoint-leaked-into-an-unprotected-stream";
    let body = endpoint_body("telemetry-4", path);

    let logs = {
        let capture = capture();
        let (status, response) = post(&dir, &body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(
            response,
            serde_json::json!({"decision": "allow"}),
            "{response}"
        );
        capture.text()
    };

    for field in [
        "request_id=telemetry-4",
        "session_id=proxy",
        "backend=cedar",
        "action=\"httpRequest\"",
        "allow=true",
        "matched=",
        "eval_us=",
    ] {
        assert!(
            logs.contains(field),
            "the INFO decision line must carry {field:?}: {logs:?}"
        );
    }

    assert!(
        !logs.contains("endpoint-leaked-into-an-unprotected-stream"),
        "the requested API path must not reach stdout at the default level — \
         stdout has none of the audit log's permissions: {logs:?}"
    );
    assert!(!logs.contains(path), "nor the target as a whole: {logs:?}");

    // Relocated, not lost.
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert!(
        lines[0]["resource"].as_str().unwrap().contains(path),
        "the audit line must still carry the whole target: {:#?}",
        lines[0]
    );
}

/// The refusal path is the one that reads like an exception and is not: an ambiguous
/// endpoint path is refused before any policy is consulted, and that refusal is
/// logged at WARN because an operator should see it without opting in — but the WARN
/// must name the *cause*, not the path. Naming the path there would put the whole
/// request target, query string and all, into an unprotected stream by default, which
/// is exactly what moving the decision detail to DEBUG was for.
#[tokio::test]
async fn an_ambiguous_endpoint_refusal_keeps_the_path_out_of_the_default_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = "/repos/../user/keys?token=refusal-leaked-at-default-level";
    let body = endpoint_body("telemetry-5", path);

    let (response, logs) = {
        let capture = capture();
        let (status, response) = post(&dir, &body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        (response, capture.text())
    };

    // The operator is still told, and can still join it to the audit line.
    assert!(
        logs.contains("WARN") && logs.contains("request_id=telemetry-5"),
        "the refusal must be visible at the default level: {logs:?}"
    );
    assert!(
        logs.contains(".."),
        "and it must name the cause it refused on: {logs:?}"
    );

    assert!(
        !logs.contains("refusal-leaked-at-default-level"),
        "the request target must not reach stdout at the default level: {logs:?}"
    );
    assert!(
        !logs.contains("/repos/"),
        "no part of the path may reach stdout at the default level: {logs:?}"
    );

    // Nothing is lost: nono is told the whole target in the reason it records, and
    // the audit log — the file with permissions — keeps both.
    assert_eq!(response["decision"], "deny", "{response}");
    assert!(
        response["reason"].as_str().unwrap().contains(path),
        "{response}"
    );
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert!(
        lines[0]["resource"].as_str().unwrap().contains(path)
            && lines[0]["reason"].as_str().unwrap().contains(path),
        "{:#?}",
        lines[0]
    );
}

/// …and the path an operator lost from the WARN is one env var away, on an event
/// carrying `request_id` so it joins the refusal it belongs to. Without this the
/// previous test would be satisfied by deleting the detail outright, which is the
/// opposite of design D6.
#[tokio::test]
async fn at_debug_the_refused_endpoint_path_is_recoverable() {
    let dir = tempfile::tempdir().unwrap();
    let path = "/repos/../user/keys?token=only-at-debug";
    let body = endpoint_body("telemetry-6", path);

    let logs = {
        let capture = capture_at(tracing::Level::DEBUG);
        let (status, response) = post(&dir, &body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        capture.text()
    };

    assert!(
        logs.contains("DEBUG"),
        "the detail must be emitted when the operator opts in: {logs:?}"
    );
    assert!(
        logs.contains(path),
        "the refused target is the first thing wanted when diagnosing this deny: \
         {logs:?}"
    );
    assert!(
        logs.matches("request_id=telemetry-6").count() >= 2,
        "the DEBUG event must repeat request_id or it cannot be joined to the \
         refusal: {logs:?}"
    );
}

/// Upstream builds `request_id` as `…-approve-{command}-{nanos}`, so the agent
/// picks part of it. Raw `ESC`/`CR` in an operator-facing log line lets a crafted
/// name erase and rewrite the decision an operator is reading.
#[tokio::test]
async fn logged_identifiers_carry_no_raw_control_bytes() {
    let hostile = "approve-git\u{1b}[2K\rINFO forged_line allow=true";
    let dir = tempfile::tempdir().unwrap();
    let allowed = command_body_with_request_id(hostile, "git", &[SHIM_GIT, "status"]);
    let refused = capability_body(hostile);
    let text = {
        let capture = capture();
        let _ = post(&dir, &allowed).await;
        let _ = post(&dir, &refused).await;
        capture.text()
    };
    assert!(
        text.contains("approve-git"),
        "the decision must be logged at all: {text:?}"
    );
    assert!(
        !text.contains('\u{1b}'),
        "raw ESC reached the operator log: {text:?}"
    );
    assert!(
        !text.contains('\r'),
        "raw CR reached the operator log: {text:?}"
    );
    assert!(
        text.contains("\\u{001b}"),
        "the escape must be visible, not dropped: {text:?}"
    );
}

/// "Internal construction failure is denied" was covered only incidentally, by a
/// test written and named for ANSI injection: it asserted a deny and the absence of
/// control bytes, so the coverage rested on Cedar's uid escaping rather than on any
/// intention, and nothing asserted the *reason* names a construction failure or that
/// the error is logged. A well-formed payload the entity builder cannot use has to
/// deny like everything else it cannot evaluate — with our reason, on the record, and
/// visible to the operator.
#[tokio::test]
async fn a_payload_that_cannot_become_a_cedar_request_is_denied_and_logged() {
    // Well-formed JSON, valid wire shape, but a raw CR cannot appear in the Cedar
    // string literal the session entity's uid is built from.
    let body = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "command",
            "request_id": "unbuildable",
            "command": "git",
            "args": [SHIM_GIT, "status"],
            "caller": "session",
            "intercept_rule": "status",
            "reason": null,
            "child_pid": 42,
            "session_id": "s1\rINFO forged allow=true"
        }
    })
    .to_string();

    let dir = tempfile::tempdir().unwrap();
    let (status, response, logs) = {
        let capture = capture();
        let (status, response) = post(&dir, &body).await;
        (status, response, capture.text())
    };

    assert_eq!(
        status,
        StatusCode::OK,
        "an internal failure must not propagate as an error to nono: {response}"
    );
    assert_eq!(response["decision"], "deny", "{response}");
    let reason = response["reason"].as_str().unwrap();
    assert!(
        reason.contains("could not build policy request"),
        "the reason must say the request could not be built, not imply a policy \
         refused it: {reason}"
    );
    assert!(
        !reason.chars().any(char::is_control),
        "the reason travels into nono's audit trail: {reason:?}"
    );
    assert!(
        logs.contains("failed to build cedar request"),
        "the operator must see the error that caused the deny: {logs:?}"
    );
    assert!(
        !logs.contains('\r'),
        "raw CR reached the operator log: {logs:?}"
    );

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0]["request_id"], "unbuildable");
    assert_eq!(lines[0]["decision"], "deny");
    assert_eq!(
        lines[0]["matched"],
        serde_json::json!([]),
        "{:#?}",
        lines[0]
    );
    assert!(
        lines[0]["reason"]
            .as_str()
            .unwrap()
            .contains("could not build policy request"),
        "{:#?}",
        lines[0]
    );
}

/// A panic must reach nono as a definite HTTP failure, not as a dropped
/// connection it can only report as a transport error.
#[tokio::test]
async fn a_panicking_handler_becomes_an_error_response() {
    async fn boom() -> &'static str {
        panic!("handler panic")
    }

    let app = server::with_middleware(
        axum::Router::new()
            .route("/boom", axum::routing::get(boom))
            .route("/ok", axum::routing::get(|| async { "fine" })),
    );

    let response = app
        .clone()
        .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let after = app
        .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "the daemon must stay available after a panic"
    );
}

/// Serializes the log-capturing tests in this binary against each other, and pins the
/// process-wide `tracing` max-level hint for the whole run.
///
/// Both halves are load-bearing, for the reason `src/test_log.rs` documents at length:
/// `set_default` installs a subscriber *thread-locally*, but `tracing` also keeps a
/// process-wide max-level hint that is recalculated whenever any thread installs or
/// drops a subscriber — so another test finishing mid-window can lower the hint,
/// silence our events before they reach the thread-local sink, and hand back an empty
/// capture. That is not hypothetical: it cost a 3/3 failure in the unit tests. This
/// file cannot use `crate::test_log` (it is `#[cfg(test)]` inside the library), so the
/// mechanism is repeated here — and it matters more now, because the DEBUG capture
/// below is the only test that raises the hint above INFO.
static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

/// A permanent global subscriber that discards output, so the max-level hint stays at
/// TRACE no matter what other threads are doing. Discarding, not printing: this must
/// not add noise to test output.
fn pin_global_level() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Ignore the error: another harness may legitimately have set one first.
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(std::io::sink)
                .finish(),
        );
    });
}

/// A live capture window. Capture ends when this is dropped, so read [`Capture::text`]
/// before then.
struct Capture {
    sink: CapturedLog,
    // Declaration order is drop order: release the subscriber before the lock, so no
    // other capturing test can start while ours is still installed.
    _subscriber: tracing::subscriber::DefaultGuard,
    _serialized: std::sync::MutexGuard<'static, ()>,
}

impl Capture {
    fn text(&self) -> String {
        self.sink.text()
    }
}

/// Begin capturing at the daemon's default level — `main.rs` defaults its
/// `EnvFilter` to `info`, so this is what an operator who set nothing sees.
fn capture() -> Capture {
    capture_at(tracing::Level::INFO)
}

/// Begin capturing everything up to `level`, for the events that are off by default.
fn capture_at(level: tracing::Level) -> Capture {
    pin_global_level();
    let serialized = match CAPTURE_LOCK.lock() {
        Ok(guard) => guard,
        // A panicking capture test must not wedge every later one.
        Err(poisoned) => poisoned.into_inner(),
    };
    let sink = CapturedLog::default();
    let subscriber = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(level)
            .with_writer(sink.clone())
            .finish(),
    );
    Capture {
        sink,
        _subscriber: subscriber,
        _serialized: serialized,
    }
}

/// `tracing` output captured into memory, so a test can assert what an operator
/// tailing the log would actually see.
#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl CapturedLog {
    fn text(&self) -> String {
        let guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        String::from_utf8_lossy(&guard).to_string()
    }
}

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = CapturedLog;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn healthz_reports_the_loaded_generation() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["generation"], 1);
    assert_eq!(json["policies"], 2, "{json}");
}

/// The third default-level event about a request, and the last one to be swept: a body
/// that fails to *parse* is refused with a WARN, and serde's error text quotes the
/// offending value verbatim — `invalid type: string "…", expected a sequence`. The
/// value it quotes came off the wire, so an argv fragment reaches stdout at the default
/// level through a field labelled `error` rather than one labelled `resource`.
///
/// The decision itself is untouched: the caller still gets `200` with a deny reason and
/// still gets an audit line. What moves is where the *detail* of the parse failure is
/// readable, on the same rule the resource summary follows — a default-level event may
/// name identifiers and causes, never request-derived content.
#[tokio::test]
async fn a_parse_failure_keeps_the_offending_value_out_of_the_default_log() {
    let dir = tempfile::tempdir().unwrap();
    // `args` must be a sequence; a string there makes serde quote it back at us.
    let body = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "command",
            "request_id": "parse-1",
            "command": "git",
            "args": "LEAKED-BY-A-SERDE-ERROR",
            "caller": "session",
            "intercept_rule": "status",
            "reason": null,
            "child_pid": 42,
            "session_id": "s1"
        }
    })
    .to_string();

    let (response, logs) = {
        let capture = capture();
        let (status, response) = post(&dir, &body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        (response, capture.text())
    };

    // Still visible, still joinable.
    assert!(
        logs.contains("WARN") && logs.contains("parse-1"),
        "the refusal must be visible at the default level: {logs:?}"
    );

    assert!(
        !logs.contains("LEAKED-BY-A-SERDE-ERROR"),
        "a request-supplied value must not reach stdout at the default level, whatever \
         field it arrives in: {logs:?}"
    );

    // Nothing is lost: the caller is told, and the audit log keeps the record.
    assert_eq!(response["decision"], "deny", "{response}");
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
}

/// And the detail is still recoverable when the operator opts in — otherwise the test
/// above would be satisfied by deleting the diagnostic, which is the opposite of D6.
#[tokio::test]
async fn a_parse_failure_reports_its_detail_at_debug() {
    let dir = tempfile::tempdir().unwrap();
    let body = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "command",
            "request_id": "parse-2",
            "command": "git",
            "args": "RECOVERABLE-AT-DEBUG",
            "caller": "session",
            "intercept_rule": "status",
            "reason": null,
            "child_pid": 42,
            "session_id": "s1"
        }
    })
    .to_string();

    let logs = {
        let capture = capture_at(tracing::Level::DEBUG);
        let (status, _) = post(&dir, &body).await;
        assert_eq!(status, StatusCode::OK);
        capture.text()
    };

    assert!(
        logs.contains("RECOVERABLE-AT-DEBUG"),
        "the parse detail must be available when the operator asks for it: {logs:?}"
    );
    assert!(
        logs.contains("parse-2"),
        "and it must be joinable to the refusal: {logs:?}"
    );
}

/// The refusal path is the *only* sink for the observed header values — a refused
/// request writes no audit line by design — so the escaping there has nothing else
/// backing it up. The approval-webhook delta makes it a SHALL ("logged at WARN with
/// the reason and the observed header values, control-escaped"), and it was
/// implemented but unpinned: nothing failed if the escaping were dropped.
///
/// **What is actually reachable through a header matters here.** DEL and the C0
/// controls cannot be tested, because they cannot arrive: `http` rejects them in a
/// field value outright (RFC 9110 limits field values to visible ASCII, space, HTAB
/// and obs-text), so the harness fails to build the request at all. What *does* arrive
/// is obs-text — bytes `0x80..=0xFF` — and `observed()` reads the raw bytes through
/// `from_utf8_lossy` rather than `to_str()`, so `0xC2 0x9B` becomes U+009B, a real C1
/// control (CSI). That is the escaping's whole job, and a C0 probe would have proved
/// nothing: the `tracing` formatter escapes C0 by itself.
#[tokio::test]
async fn control_bytes_in_the_refused_headers_are_escaped_in_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    // U+009B (CSI) as UTF-8 obs-text: 0xC2 0x9B, which a header value may carry.
    let hostile_type = "text/plain\u{9b}31mFORGED";
    let hostile_origin = "https://evil.example\u{9b}0m";

    let logs = {
        let capture = capture();
        // 415 path: the observed content-type is what gets logged.
        let (status, _) = post_with_headers(
            &app,
            &[("content-type", hostile_type)],
            &command_body("git", &[nono_cedar_pdp::wire::EXAMPLE_SHIM_ARGV0, "status"]),
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        // 403 path: the observed origin is what gets logged.
        let (status, _) = post_with_headers(
            &app,
            &[
                ("content-type", "application/json"),
                ("origin", hostile_origin),
            ],
            &command_body("git", &[nono_cedar_pdp::wire::EXAMPLE_SHIM_ARGV0, "status"]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        capture.text()
    };

    assert!(
        !logs.contains('\u{9b}'),
        "a raw CSI from a refused request's headers reached the log: {logs:?}"
    );
    // Escaped, not dropped: an operator still sees what was probed with.
    assert!(
        logs.contains("\\u{009b}"),
        "the observed value must survive, escaped: {logs:?}"
    );
    assert!(
        logs.contains("FORGED") && logs.contains("evil.example"),
        "and must still name what was sent: {logs:?}"
    );

    // The premise of the test: neither refusal wrote an audit line.
    assert!(
        audit_lines(&dir).is_empty(),
        "a refusal must not be audited"
    );
}

/// #7. `/healthz` is unauthenticated, and the absolute policy directory it used to
/// report is precisely the target of the policy-rewrite escalation the isolation
/// checks exist to close. Asserted on a daemon whose reload was **refused**, because
/// that is the state in which an error string — which names the file it failed on —
/// would leak the same thing back through the new field.
#[tokio::test]
async fn healthz_names_no_path_and_no_reload_error() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(&dir);
    st.last_reload.store(Some(Arc::new(watcher::LastReload {
        outcome: "refused",
        at: "2026-07-26T19:00:00Z".to_string(),
    })));
    let policy_dir = dir.path().display().to_string();
    let (status, json) = healthz_of(st).await;

    assert_eq!(status, StatusCode::OK);
    let body = json.to_string();
    assert!(
        !body.contains(&policy_dir),
        "the policy directory must not be disclosed by an unauthenticated \
         endpoint: {body}"
    );
    assert!(
        !body.contains(".cedar"),
        "no policy file path may appear either: {body}"
    );
    assert!(
        json.get("policy_dir").is_none(),
        "the field must be gone, not merely empty: {body}"
    );
}

/// Design §7 promised operators "generation + load time". `loaded_at` has been
/// written on every load since the engine was built; this is the first thing that
/// ever read it.
#[tokio::test]
async fn healthz_reports_when_the_active_set_was_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let (_status, json) = healthz_of(state(&dir)).await;
    let loaded_at = json["loaded_at"]
        .as_str()
        .unwrap_or_else(|| panic!("no loaded_at: {json}"));
    assert!(
        loaded_at.contains('T') && loaded_at.ends_with('Z'),
        "want RFC 3339 UTC: {loaded_at}"
    );
}

#[tokio::test]
async fn healthz_reports_no_reload_before_one_has_been_attempted() {
    let dir = tempfile::tempdir().unwrap();
    let (_status, json) = healthz_of(state(&dir)).await;
    assert!(
        json["last_reload"].is_null(),
        "a synthesised record of the bootstrap load would make \"has anything \
         happened since startup\" unanswerable: {json}"
    );
}

/// The monitoring gap this change exists to close: a refused or failed reload keeps
/// the last-known-good set deciding — correct, and fail-closed — while the
/// generation and count look exactly like a healthy daemon.
#[tokio::test]
async fn healthz_reports_a_refused_reload_while_the_last_good_set_keeps_deciding() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(&dir);
    st.last_reload.store(Some(Arc::new(watcher::LastReload {
        outcome: "refused",
        at: "2026-07-26T19:00:00Z".to_string(),
    })));
    let (status, json) = healthz_of(st).await;

    assert_eq!(json["last_reload"]["outcome"], "refused", "{json}");
    assert_eq!(json["last_reload"]["at"], "2026-07-26T19:00:00Z");
    assert_eq!(
        json["generation"], 1,
        "the generation must still describe the set that is deciding: {json}"
    );
    assert_eq!(json["policies"], 2, "{json}");
    assert_eq!(
        status,
        StatusCode::OK,
        "a daemon serving its last-known-good set is healthy"
    );
}

/// Kept as its own test because it is the thing a future reader is most likely to
/// "fix" the wrong way. A failed reload must NOT make this 503: that invites an
/// orchestrator to restart the daemon, the restart re-runs the bootstrap load
/// against the same broken directory, startup fails and the process exits — and
/// nono then gets connection refused and fails closed on every action. The remedy
/// would be far worse than the condition, and it would fire exactly when an
/// operator has just mistyped a policy file.
#[tokio::test]
async fn a_failed_reload_does_not_make_the_daemon_report_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(&dir);
    st.last_reload.store(Some(Arc::new(watcher::LastReload {
        outcome: "failed",
        at: "2026-07-26T19:00:00Z".to_string(),
    })));
    let (status, json) = healthz_of(st).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["last_reload"]["outcome"], "failed");
}
