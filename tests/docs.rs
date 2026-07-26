//! Guards on the two documents an operator actually acts on: `README.md` and the
//! example nono profile.
//!
//! These exist because the documentation rotted in exactly the way an untested
//! document does. The README's rollout table told an operator to switch
//! `approval_defaults.backend` to `cedar-and-ask`, and
//! `examples/cedar-pdp-smoke.json` never defined that backend — so nono's own
//! validator rejected the documented step with
//! `unknown_approval_backend`, and the whole suite stayed green.
//!
//! What is asserted here is structure and presence, not prose: the backends the
//! table names exist in the shipped profile, the profile's chains resolve, and the
//! passages the spec requires an author or operator to find are still there. Only
//! `just smoke` can run nono's real validator (it needs the `nono` binary), so this
//! reproduces the one rule that validator applies to a backend reference.
#![allow(clippy::unwrap_used, clippy::panic)]

const README: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"));
const PROFILE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/cedar-pdp-smoke.json"
));

/// The `approval_backends` map of the shipped example profile.
fn profile_backends() -> serde_json::Map<String, serde_json::Value> {
    let profile: serde_json::Value = serde_json::from_str(PROFILE)
        .unwrap_or_else(|e| panic!("examples/cedar-pdp-smoke.json is not valid JSON: {e}"));
    profile["command_policies"]["approval_backends"]
        .as_object()
        .unwrap_or_else(|| panic!("the example profile defines no approval_backends: {profile:#}"))
        .clone()
}

/// The backend column of the rollout-posture table, in document order. Panics if the
/// table is gone: a README that no longer documents the postures must fail this test
/// rather than pass it with nothing to check.
fn documented_rollout_backends() -> Vec<String> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in README.lines() {
        let trimmed = line.trim();
        if !in_table {
            let header = trimmed.replace(' ', "").to_lowercase();
            in_table = header.starts_with("|posture|backend|");
            continue;
        }
        if !trimmed.starts_with('|') {
            break;
        }
        let cells: Vec<&str> = trimmed.trim_matches('|').split('|').collect();
        let Some(backend) = cells.get(1) else {
            continue;
        };
        let backend = backend.trim().trim_matches('`').trim();
        // The `|---|---|` separator row.
        if backend.chars().all(|c| c == '-' || c == ':') || backend.is_empty() {
            continue;
        }
        rows.push(backend.to_string());
    }
    assert!(
        !rows.is_empty(),
        "no rollout-posture table found in README.md — the postures are a spec \
         requirement, so their table cannot simply disappear"
    );
    rows
}

/// The documentation is the only way an operator learns which posture to select, and
/// nono rejects an `approval_defaults.backend` (or a chained backend) that is not
/// defined: a posture the docs name and the profile does not define is a step the
/// operator cannot take.
#[test]
fn every_documented_rollout_backend_is_defined_in_the_example_profile() {
    let backends = profile_backends();
    let documented = documented_rollout_backends();
    assert!(
        documented.len() >= 3,
        "three postures are documented (fallback, enforce, mandatory confirmation), \
         found {documented:?}"
    );
    for backend in &documented {
        assert!(
            backends.contains_key(backend),
            "the rollout table names backend {backend:?}, which \
             examples/cedar-pdp-smoke.json does not define — nono's profile validator \
             rejects that with unknown_approval_backend. Defined: {:?}",
            backends.keys().collect::<Vec<_>>()
        );
    }

    // The other direction, so the example cannot grow a backend nobody documents.
    // A bare `contains`, not a backticked search: the README names some of these
    // inside JSON snippets.
    for name in backends.keys() {
        assert!(
            README.contains(name.as_str()),
            "the example profile defines backend {name:?} that the README never \
             mentions"
        );
    }
}

/// The chain postures are the documented safe-rollout mechanism — there is no
/// dry-run mode in the daemon precisely because nono composes backends — so the
/// shapes the table promises have to be the shapes the profile ships: `any` for the
/// posture that falls back to a prompt, `all` for the one that demands both.
#[test]
fn the_documented_chain_postures_have_the_modes_the_table_promises() {
    let backends = profile_backends();
    let mut modes = Vec::new();
    for (name, backend) in &backends {
        if backend["type"] != "chain" {
            continue;
        }
        let mode = backend["mode"]
            .as_str()
            .unwrap_or_else(|| panic!("chain backend {name:?} defines no mode; nono rejects that"));
        let members: Vec<&str> = backend["backends"]
            .as_array()
            .unwrap_or_else(|| panic!("chain backend {name:?} defines no backends"))
            .iter()
            .map(|m| m.as_str().unwrap_or_default())
            .collect();
        assert!(
            !members.is_empty(),
            "chain backend {name:?} has an empty member list; nono rejects that"
        );
        for member in &members {
            assert_ne!(
                member, name,
                "chain backend {name:?} cannot chain to itself"
            );
            assert!(
                backends.contains_key(*member),
                "chain backend {name:?} references undefined backend {member:?}"
            );
        }
        assert!(
            members.contains(&"cedar"),
            "a Cedar rollout posture must include the cedar backend: {name} -> {members:?}"
        );
        assert!(
            members.contains(&"terminal"),
            "both documented chain postures fall back to (or demand) a human: \
             {name} -> {members:?}"
        );
        modes.push(mode.to_string());
    }
    modes.sort();
    assert_eq!(
        modes,
        vec!["all".to_string(), "any".to_string()],
        "the table documents a chain in `any` mode (Cedar denies, then a prompt) and \
         one in `all` mode (Cedar *and* a human), so the profile must define both"
    );
}

/// The README's `command_policies` snippet is what an operator pastes into their own
/// profile. If it drifts from the shipped example, the operator's profile cannot take
/// the documented posture even though the example can.
#[test]
fn the_readme_snippet_defines_the_same_backends_as_the_shipped_profile() {
    let mut snippet = None;
    let mut current: Option<String> = None;
    for line in README.lines() {
        match (line.trim_start().starts_with("```"), &mut current) {
            (true, None) => current = Some(String::new()),
            (true, Some(block)) => {
                if block.contains("approval_backends") {
                    snippet = Some(block.clone());
                    break;
                }
                current = None;
            }
            (false, Some(block)) => {
                block.push_str(line);
                block.push('\n');
            }
            (false, None) => {}
        }
    }
    let snippet =
        snippet.unwrap_or_else(|| panic!("no fenced block defining approval_backends in README"));
    let parsed: serde_json::Value = serde_json::from_str(&snippet).unwrap_or_else(|e| {
        panic!("the README's approval_backends snippet is not valid JSON ({e}): {snippet}")
    });
    let documented = parsed["command_policies"]["approval_backends"]
        .as_object()
        .unwrap_or_else(|| panic!("snippet has no command_policies.approval_backends: {snippet}"));

    let shipped = profile_backends();
    let mut documented_names: Vec<&String> = documented.keys().collect();
    let mut shipped_names: Vec<&String> = shipped.keys().collect();
    documented_names.sort();
    shipped_names.sort();
    assert_eq!(
        documented_names, shipped_names,
        "the README snippet and examples/cedar-pdp-smoke.json must define the same \
         approval backends"
    );
    for (name, backend) in documented {
        assert_eq!(
            backend["type"], shipped[name]["type"],
            "backend {name:?} has a different type in the README than in the profile"
        );
        assert_eq!(
            backend["mode"], shipped[name]["mode"],
            "backend {name:?} has a different chain mode in the README than in the \
             profile"
        );
    }
}

/// The passages the spec's documentation scenarios require. Substrings, deliberately
/// short and load-bearing: the point is that a future edit cannot silently delete the
/// guidance that keeps a policy author from writing a fail-open rule, or the operator
/// from mistaking an unauthenticated webhook for an authenticated one.
#[test]
fn the_documented_caveats_and_risks_are_still_in_the_readme() {
    for (scenario, needle) in [
        // Argument-matching guidance: membership for flags, an anchored argv_tail
        // test for the subcommand, and wildcard-leading globs in forbid only.
        (
            "test flags by set membership",
            "resource.args.contains(\"--force\")",
        ),
        (
            "pin a subcommand positionally",
            "resource.argv_tail == \"status\" || resource.argv_tail like \"status *\"",
        ),
        (
            "membership cannot express position",
            "cannot express POSITION",
        ),
        ("unanchored globs are forbid-only", "forbid-only"),
        // The args[0] shim-path contract, and that reading argv fails to load.
        ("args[0] is a per-run shim path", "shims/git"),
        (
            "a policy reading argv will not load",
            "fails strict validation",
        ),
        // The dropped-argument blind spot. "Positions shift" was the weaker thing this
        // repo used to say; these pin the stronger, true one — the entry is gone, so a
        // forbid naming it fails open, and no authoring care avoids it.
        (
            "a non-UTF-8 argv entry is dropped rather than converted",
            "dropped, not converted",
        ),
        (
            "a dropped entry is absent from both attributes",
            "absent from `args` and from `argv_tail`",
        ),
        (
            "a rule cannot match an argument it cannot see",
            "cannot match one it cannot see",
        ),
        (
            "an argument-naming forbid fails open, not merely over- or under-denies",
            "in a `forbid` that is fail-open",
        ),
        (
            "which matching shapes survive the drop",
            "occupies its own argv entry",
        ),
        (
            "the drop is not avoidable by careful authoring",
            "byte-identical",
        ),
        ("the drop closes only upstream", "preserving arity"),
        // The raw-path caveat.
        ("endpoint paths arrive raw", "denied outright"),
        // The header gate: what an operator driving the endpoint by hand must send,
        // and the one-flag fix, since the failure mode is a 415 rather than a deny.
        (
            "the decide endpoint requires a JSON content-type",
            "Content-Type: application/json",
        ),
        (
            "the one-flag fix for anyone POSTing by hand",
            "-H 'Content-Type: application/json'",
        ),
        ("a request carrying an Origin is refused", "`Origin`"),
        // The residual, in the same words as the spec and the module docs: recording
        // the User-Agent must never read as authenticating the caller.
        (
            "none of this authenticates nono",
            "none of this authenticates nono",
        ),
        (
            "a local process as the same user can still forge a record",
            "forge an audit record",
        ),
        (
            "the User-Agent is evidence, not verification",
            "not verification",
        ),
        // Raising the log level relocates the audit log's content into a stream with
        // none of its permissions.
        (
            "DEBUG output has the audit log's sensitivity without its permissions",
            "without its permissions",
        ),
        // Impersonation risk, loopback-only, and the planned mitigation.
        (
            "nono cannot authenticate the decider",
            "cannot authenticate the decider",
        ),
        (
            "loopback is the access control",
            "non-loopback `bind` is a hard config error",
        ),
        ("https on loopback is the mitigation", "https on loopback"),
        // The fallback posture, described as what it does.
        (
            "a Cedar denial becomes a prompt",
            "then you get a terminal prompt",
        ),
        // The state-path isolation section. The profile-checking procedure is
        // the one control that works against the sandboxed agent, so it must
        // stay findable: the resolved-manifest command, and the per-command
        // fs_write/fs_write_file sweep the resolved manifest omits.
        (
            "the profile-checking procedure: resolved grants",
            "nono profile show <profile> --format manifest",
        ),
        (
            "the profile-checking procedure: per-command grants",
            "fs_write_file",
        ),
        // Why a /tmp-style 1777 chain is fine while a 770 parent is not — and
        // why the same exemption never applies to the policy dir itself.
        (
            "the sticky-ancestor rationale",
            "sticky does not restrict creation",
        ),
        // The ownership rule: modes answer who may write, ownership answers who
        // may change the answer.
        (
            "the ownership rule",
            "owned by neither the daemon's user nor root",
        ),
        // The https-on-loopback operator path: the block to write, and the two
        // things about it a reader will otherwise get wrong.
        (
            "the [tls] block, with the home-anchored default paths",
            "cert = \"~/.config/nono-cedar-pdp/tls/cert.pem\"",
        ),
        (
            "the URL names the literal bind address, never a hostname (T5)",
            "names the literal address",
        ),
        (
            "why `localhost` is not that address — the resolver picks the listener",
            "resolves `::1` before `127.0.0.1`",
        ),
        (
            "and what that costs: every localhost request reaches the squatter",
            "reaches the squatter",
        ),
        (
            "a locally-minted certificate is trusted through a user-added anchor (T7)",
            "user-added trust anchor",
        ),
        (
            "a self-signed leaf dropped in a keychain is not one",
            "is not a substitute",
        ),
        (
            "and `security verify-cert` is not the way to check any of it",
            "security verify-cert",
        ),
        // What TLS does not buy, in the accepted-risk register's voice. The
        // wording is the control here for the same reason it is in A02: the
        // failure mode of this feature is a reader who remembers the headline.
        (
            "TLS buys nothing against same-uid code that can read the key",
            "same-uid code that can read the private key",
        ),
        (
            "TLS says nothing about nono's identity",
            "Nothing about nono's identity",
        ),
        (
            "availability is traded away deliberately, not overlooked",
            "prefers an outage to a silent bypass",
        ),
        (
            "a caught squatter is a transport error, not a recorded denial (T1)",
            "the command exits 126",
        ),
        // The openssl fallback for operators without mkcert. Both extensions are
        // load-bearing: without the EKU or without the address in the SANs the
        // verifier refuses the leaf, and the operator learns that at startup,
        // after the trust-store step that needed an admin password.
        (
            "the fallback leaf carries the serverAuth EKU",
            "extendedKeyUsage=serverAuth",
        ),
        (
            "the fallback leaf carries all three loopback names",
            "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
        ),
    ] {
        // Matched against the README with every whitespace run collapsed, so
        // re-wrapping a paragraph is not a test failure — only deleting the guidance
        // is.
        assert!(
            flowed(README).contains(&flowed(needle)),
            "README.md no longer documents {scenario:?} (looked for {needle:?})"
        );
    }
}

/// `text` with every run of whitespace collapsed to one space.
fn flowed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// The fenced block whose body contains `needle`, without its fence lines.
fn fenced_block_containing(needle: &str) -> String {
    let mut current: Option<String> = None;
    for line in README.lines() {
        match (line.trim_start().starts_with("```"), &mut current) {
            (true, None) => current = Some(String::new()),
            (true, Some(block)) => {
                if block.contains(needle) {
                    return block.clone();
                }
                current = None;
            }
            (false, Some(block)) => {
                block.push_str(line);
                block.push('\n');
            }
            (false, None) => {}
        }
    }
    panic!("no fenced block in README.md contains {needle:?}");
}

/// The `openssl` fallback for operators without `mkcert` — **run**, not read.
///
/// A minting recipe fails in two ways the daemon's refusal cannot help an operator
/// debug, because both arrive at startup and long after the admin-password step: a
/// leaf without the `serverAuth` EKU, and a leaf missing the loopback address the
/// daemon binds. Neither is visible in the files it produced. So the documented
/// block is executed here into a temporary directory, and the leaf it wrote is put
/// in front of a real webpki verifier — the code path that decides, rather than a
/// grep over `openssl x509 -text`, which would pass on a certificate carrying the
/// right words in the wrong place.
///
/// Only the *minting* half runs. Installing the CA as a trust anchor needs an
/// administrator, and it is the daemon's own T6 self-test that tells the operator
/// whether that step worked — this test cannot do it and must not try.
///
/// The verifier is given the block's own CA as its only root, which is what makes
/// this a test of the recipe rather than of this machine's trust store: it asks
/// "would a verifier that trusts this CA accept this leaf for `127.0.0.1`", which
/// is exactly what the operator's platform verifier will be asked once the anchor
/// is installed.
///
/// Measured while mutating the block, and recorded because it bounds what this
/// test can claim: dropping an address from `subjectAltName` reddens it
/// (`NotValidForName`), and naming a *different* EKU reddens it ("does not allow
/// extended key usage for server authentication") — but deleting the
/// `extendedKeyUsage` line altogether does **not**, because an absent EKU extension
/// is unrestricted. That one is held by the README needle above instead.
#[test]
fn the_documented_openssl_fallback_mints_a_leaf_a_verifier_accepts() {
    use rustls::client::danger::ServerCertVerifier;

    // Selected on the CA's subject rather than on either extension: both
    // extensions are things this test has to be able to *see removed*, and a
    // selector that is itself the mutation target turns a verification failure
    // into "no such block", which is red for the wrong reason.
    let block = fenced_block_containing("nono-cedar-pdp local CA");
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&block)
        .env("TLS_DIR", dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the README's openssl fallback does not run: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let read_pem = |name: &str| {
        let pem = std::fs::read(dir.path().join(name)).unwrap_or_else(|e| {
            panic!("the documented fallback wrote no {name} ({e}): {}", &block)
        });
        rustls_pemfile::certs(&mut pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("{name} is not a certificate: {e}"))
    };
    let mut chain = read_pem("cert.pem");
    assert!(!chain.is_empty(), "the fallback wrote an empty cert.pem");
    let leaf = chain.remove(0);

    let mut roots = rustls::RootCertStore::empty();
    for ca in read_pem("ca.pem") {
        roots.add(ca).unwrap();
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        std::sync::Arc::new(roots),
        provider,
    )
    .build()
    .unwrap();
    // Every address the shipped configuration accepts. `127.0.0.1` is the
    // documented default; `::1` is the one an operator reaches by writing
    // `localhost` anywhere, which T5 is about.
    for name in [
        rustls::pki_types::ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()),
        rustls::pki_types::ServerName::IpAddress(std::net::Ipv6Addr::LOCALHOST.into()),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    ] {
        verifier
            .verify_server_cert(
                &leaf,
                &chain,
                &name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap_or_else(|e| {
                panic!(
                    "the leaf the documented fallback mints is refused for {name:?}: {e} \
                     — an operator following it installs a CA with an admin password and \
                     then gets a daemon that will not start"
                )
            });
    }
    // The negative row, for the same reason the IP-SAN measurement has one: it is
    // what proves the three above mean "this certificate covers these names"
    // rather than "this verifier accepts anything from that CA".
    assert!(
        verifier
            .verify_server_cert(
                &leaf,
                &chain,
                &rustls::pki_types::ServerName::try_from("example.com").unwrap(),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .is_err(),
        "the fallback's leaf is accepted for a name it does not carry, so the rows \
         above prove nothing about its SANs"
    );
}
