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
///
/// Every needle must match **exactly once**, and that is the assertion rather than
/// `contains`. A needle matching twice is not a stricter test, it is a vacuous one:
/// the passage it claims to pin can be deleted whole and the other match keeps it
/// green. Measured — `"is not a substitute"` also matched an unrelated sentence about
/// the working-directory warning eight sections away, so the "a self-signed leaf is
/// not an anchor" guidance was deletable with the suite green, and seven more needles
/// were in the same state. Zero is the guidance gone; more than one means the needle
/// no longer names one passage, so narrow it to a phrase only that passage has.
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
        (
            "args[0] is a per-run shim path",
            "`args[0]` is not the command name",
        ),
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
            "`Content-Type: application/json` is required",
        ),
        (
            "the one-flag fix for anyone POSTing by hand",
            "-H 'Content-Type: application/json'",
        ),
        (
            "a request carrying an Origin is refused",
            "A request carrying an `Origin` header is `403`",
        ),
        // The residual, in the same words as the spec and the module docs: recording
        // the User-Agent must never read as authenticating the caller.
        (
            "none of this authenticates nono",
            "none of this authenticates nono",
        ),
        (
            "a local process as the same user can still forge a record",
            "still forge an audit record that is indistinguishable",
        ),
        (
            "the User-Agent is evidence, not verification",
            "is evidence, **not verification**",
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
        (
            "https on loopback is the mitigation",
            "closes the outbound half",
        ),
        // The fallback posture, described as what it does.
        (
            "a Cedar denial becomes a prompt",
            "then you get a terminal prompt",
        ),
        // The state-path isolation section. The profile-checking procedure is
        // the one control that works against the sandboxed agent, so it must
        // stay findable: the resolved-manifest command, and the per-command
        // fs_write/fs_write_file sweep the resolved manifest omits.
        // The whole command, not just `nono profile show … --format manifest`,
        // which now appears twice: once for the write sweep and once for the read
        // one. Two commands doing different jobs are not two chances to pass.
        (
            "the profile-checking procedure: resolved write grants",
            "nono profile show <profile> --format manifest \\ | jq -r \
             '.filesystem.grants[] | select(.access | test(\"write\"))",
        ),
        (
            "the profile-checking procedure: per-command grants",
            "fs_write_file // []",
        ),
        // And the same procedure for the key, whose grant kind is the other one.
        // `just smoke-tls` asserts this against its own generated profile; the
        // README is where an operator gets it for theirs, and it was write-only
        // while the key's whole rule is read.
        (
            "the profile-checking procedure: the key's rule is read, not write",
            "the private key's rule is READ, not write",
        ),
        (
            "the profile-checking procedure: resolved read grants",
            "nono profile show <profile> --format manifest \\ | jq -r \
             '.filesystem.grants[] | select(.access | test(\"read\"))",
        ),
        (
            "the profile-checking procedure: per-command read grants",
            "fs_read_file // []",
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
            "it is not an anchor",
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
        // The anchor step is the one part of the fallback no test can run — it
        // needs an administrator — and it is also the one that costs a password
        // to get wrong. The CA now lives beside the daemon's directory rather
        // than in it, so this is the line that has to have moved with it: pointed
        // at `$TLS_DIR/ca.pem` it installs nothing and the operator finds out at
        // the next startup, from a refusal about the leaf.
        (
            "the fallback installs the CA from where the block actually wrote it",
            "-k /Library/Keychains/System.keychain \"$CA_DIR/ca.pem\"",
        ),
    ] {
        // Matched against the README with every whitespace run collapsed, so
        // re-wrapping a paragraph is not a test failure — only deleting the guidance
        // is.
        let hits = flowed(README).matches(&flowed(needle)).count();
        assert_eq!(
            hits, 1,
            "README.md documents {scenario:?} in {hits} places (looked for \
             {needle:?}). Zero means the guidance is gone. More than one means this \
             needle no longer pins the passage it names — the passage can be deleted \
             whole and the other match keeps this test green — so narrow it to a \
             phrase only that passage has."
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
///
/// The file *placement* is asserted here too, because it is a security property
/// and prose alone had it wrong: the block used to `cd "$TLS_DIR"` and mint the CA
/// there, so `ca-key.pem` landed in the directory the `[tls]` block names — eight
/// lines above prose saying that key "belongs nowhere near the daemon". A read
/// grant on that tree (A04) then yielded not just the serving key but a CA key good
/// for **any name this machine trusts**, which is strictly wider than A04 states.
#[test]
fn the_documented_openssl_fallback_mints_a_leaf_a_verifier_accepts() {
    use rustls::client::danger::ServerCertVerifier;

    // Selected on the CA's subject rather than on either extension: both
    // extensions are things this test has to be able to *see removed*, and a
    // selector that is itself the mutation target turns a verification failure
    // into "no such block", which is red for the wrong reason.
    let block = fenced_block_containing("nono-cedar-pdp local CA");
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tls");
    let ca_dir = root.path().join("ca");
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&block)
        .env("TLS_DIR", &dir)
        .env("CA_DIR", &ca_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the README's openssl fallback does not run: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Exactly the two files the `[tls]` block names, and nothing else. The CA's
    // key is the one that matters — it signs future leaves, so whoever reads it
    // mints a certificate this machine trusts for any name at all — but the
    // assertion is the whole set rather than that one name, because a serial file
    // or a leftover CSR in the daemon's directory is the same mistake made
    // smaller, and `just mint-cert` leaves exactly these two.
    let mut left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec!["cert.pem".to_string(), "key.pem".to_string()],
        "the documented fallback left {left:?} in the directory the [tls] block \
         names. Only `cert` and `key` belong there: the CA's private key signs \
         future leaves and belongs nowhere near the daemon, and a read grant on \
         this tree hands over everything in it (A04)."
    );

    let read_pem = |at: &std::path::Path, name: &str| {
        let pem = std::fs::read(at.join(name)).unwrap_or_else(|e| {
            panic!("the documented fallback wrote no {name} ({e}): {}", &block)
        });
        rustls_pemfile::certs(&mut pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("{name} is not a certificate: {e}"))
    };
    let mut chain = read_pem(&dir, "cert.pem");
    assert!(!chain.is_empty(), "the fallback wrote an empty cert.pem");
    let leaf = chain.remove(0);

    let mut roots = rustls::RootCertStore::empty();
    for ca in read_pem(&ca_dir, "ca.pem") {
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

/// The documented fallback is the *other* path to the same pair, so it has to
/// refuse an existing one for the reason `just mint-cert` does — and did not.
///
/// `just_mint_cert_refuses_to_overwrite_an_existing_pair` states the reason
/// verbatim: the running daemon is serving the old certificate, the operator's own
/// CA may have signed it, and the file is the only copy of the key. None of that
/// gets less true because the operator has no `mkcert`. Measured before the guard
/// existed: writing a sentinel `key.pem` and running the block replaced it and
/// exited 0.
///
/// Each of the three files is checked on its own run, because a guard that only
/// looks at the first one it happens to reach is the same defect one file along —
/// and `ca-key.pem` is the one whose loss is worst, since every leaf the operator
/// has ever signed with it chains to a CA they can no longer reissue from.
#[test]
fn the_documented_openssl_fallback_refuses_to_overwrite_an_existing_pair() {
    let block = fenced_block_containing("nono-cedar-pdp local CA");
    const SENTINEL: &str = "the operator's real file\n";

    for (subdir, name) in [
        ("tls", "cert.pem"),
        ("tls", "key.pem"),
        ("ca", "ca-key.pem"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("tls");
        let ca_dir = root.path().join("ca");
        let existing = root.path().join(subdir).join(name);
        std::fs::create_dir_all(root.path().join(subdir)).unwrap();
        std::fs::write(&existing, SENTINEL).unwrap();

        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&block)
            .env("TLS_DIR", &dir)
            .env("CA_DIR", &ca_dir)
            .output()
            .unwrap();
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&existing).unwrap(),
            SENTINEL,
            "the documented fallback overwrote an existing {name}, which is the \
             only copy of what it replaced: {said}"
        );
        assert!(
            !out.status.success(),
            "the documented fallback found an existing {name} and exited 0, which \
             reads as success: {said}"
        );
        assert!(
            said.contains(name),
            "the refusal must name the file that stopped it, or the operator \
             cannot act on it: {said}"
        );
    }
}

/// The anchor step has to install the CA the block before it actually wrote.
///
/// It is the one part of the fallback no test can run for real — it needs an
/// administrator — and the one that costs a password to get wrong: pointed at a
/// path nothing was written to, `security add-trusted-cert` installs nothing, and
/// the operator learns that at the daemon's next startup from a refusal about the
/// *leaf*, which does not mention the anchor at all.
///
/// It is a *separate shell command* from the block that mints, so it depends on
/// `$CA_DIR` surviving between them. Neither `tests/docs.rs` nor a reader notices
/// that if the environment already carries the variable — so this test deliberately
/// sets neither `TLS_DIR` nor `CA_DIR`, and overrides `HOME` instead, which is the
/// operator's situation exactly: whatever the block's own defaults are, the anchor
/// step must resolve to the same place. Measured while writing it: with the
/// assignments inside the minting subshell the anchor step ran on `/ca.pem`.
///
/// `sudo` and `security` are shimmed onto `PATH` — the first to run its argument
/// without privileges, the second to record what it was handed. Shimming rather
/// than parsing, so a change to the command's flags cannot make this pass by
/// matching a string that no longer means what it did.
#[test]
fn the_documented_anchor_step_installs_the_ca_the_block_wrote() {
    let mint = fenced_block_containing("nono-cedar-pdp local CA");
    let anchor = fenced_block_containing("add-trusted-cert");
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let recorded = home.path().join("anchored");

    let shim = |name: &str, body: String| {
        use std::os::unix::fs::PermissionsExt;
        let path = bin.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    shim("sudo", "#!/bin/sh\nexec \"$@\"\n".to_string());
    // The last argument is the file being trusted, whatever the flags before it.
    shim(
        "security",
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do :; done\nprintf '%s' \"$a\" > '{}'\n",
            recorded.display()
        ),
    );

    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(format!("{mint}\n{anchor}"))
        .env("HOME", home.path())
        .env_remove("TLS_DIR")
        .env_remove("CA_DIR")
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the documented mint-then-anchor sequence does not run: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let anchored = std::fs::read_to_string(&recorded)
        .unwrap_or_else(|e| panic!("the anchor step ran no `security` command ({e})"));
    let anchored = std::path::PathBuf::from(&anchored);
    assert!(
        anchored.is_file(),
        "the documented anchor step installs {anchored:?}, which the block before it \
         never wrote — so it trusts nothing, silently, after asking for an admin \
         password. The operator finds out at the daemon's next startup, from a \
         refusal that talks about the leaf."
    );
    let pem = std::fs::read(&anchored).unwrap();
    let certs = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("{anchored:?} is not a certificate: {e}"));
    assert_eq!(
        certs.len(),
        1,
        "the anchor step must install exactly one certificate: {anchored:?}"
    );
    // The CA and not the leaf: installing the leaf is the mistake the section
    // above this block exists to talk an operator out of, so the block must not
    // then do it.
    assert!(
        home.path().join(".config/nono-cedar-pdp/ca/ca.pem") == anchored,
        "the anchor step installs {anchored:?} rather than the CA the block minted \
         — a leaf in a keychain is not an anchor, which is the whole point of this \
         section"
    );
}

const JUSTFILE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Justfile"));

/// The body of one `just` recipe, so a needle satisfied by a *different* recipe
/// cannot stand in for it — `mkcert -install` appears in `mint-cert` as well.
fn recipe(name: &str) -> String {
    let mut body: Option<String> = None;
    for line in JUSTFILE.lines() {
        match &mut body {
            None => {
                let head = line.split_whitespace().next().unwrap_or_default();
                if head == format!("{name}:") || head == name {
                    body = Some(String::new());
                }
            }
            Some(collected) => {
                if !line.is_empty() && !line.starts_with([' ', '\t']) {
                    return collected.clone();
                }
                collected.push_str(line);
                collected.push('\n');
            }
        }
    }
    body.unwrap_or_else(|| panic!("the Justfile has no `{name}` recipe"))
}

/// `body` with every whole-line comment removed, which is what the needles below
/// are matched against.
///
/// Measured, and the reason this function exists: with the comments left in, the
/// per-arm skip guard stayed **green** after `echo "      mkcert -install"` was
/// deleted from the T6 refusal arm, because the comment eight lines above it
/// explains that the daemon's refusal "names `mkcert -install`". A recipe's
/// comments are prose about the checks; a guard that a comment can satisfy is
/// pinning the prose and not the check, which is the exact defect these needles
/// were tightened to close.
fn code_of(body: &str) -> String {
    body.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// `just smoke-tls` is the only verification that drives real nono against a
/// squatter, and nothing in `cargo test` can run it: it needs the `nono` binary,
/// `nono setup` to have been run, and a local CA installed by a human with an admin
/// password. So what is pinned here is the handful of details that decide whether a
/// *run* of it means anything at all.
///
/// Each of these has a specific way of failing silently:
///
/// - The block has to be asserted as **exit 126 specifically**. Both of nono's
///   blocking paths — `Err(SandboxInit)` from a transport failure and
///   `Err(BlockedCommand)` from a policy denial — reach the same `write_response(…,
///   126, …)` in upstream's `handle_shim_stream`, so "non-zero" would be satisfied
///   by the daemon simply denying, which is not what this proves.
/// - Which is why the recipe also has to read the **message**: `approval_denied` is
///   the denial shape and must be absent, `Sandbox initialization failed` is the
///   transport shape and must be present. That distinction is T1, and it is the
///   thing a future reader will get wrong.
/// - The **read**-grant sweep over the resolved manifest. The write sweep beside it
///   is the policy directory's and the audit log's rule; a private key is handed
///   over completely by a *read* grant, so a profile that only reads the TLS tree
///   passes the write sweep in silence (A04).
///
/// Every needle is the **assertion's own text**, matched exactly once, rather than a
/// word from the prose around it — and that is the whole lesson of this test's own
/// history. `"126"` matched four comments and echoes as well as the `if` that tests
/// it, so the exit-code check this docstring calls the point of the recipe could be
/// deleted whole with this green; `"mkcert -install"` matched four places the same
/// way. A needle a comment can satisfy pins a comment.
///
/// The skip is pinned by
/// [`every_early_success_in_the_squat_recipe_announces_itself_as_a_skip`], which has
/// to reason per-arm and cannot be a needle here at all.
#[test]
fn the_squat_recipe_keeps_what_makes_a_run_of_it_mean_something() {
    let body = code_of(&recipe("smoke-tls"));
    for (why, needle) in [
        (
            "the block is asserted as exit 126, not merely non-zero (T1)",
            "[ \"$CODE\" -ne 126 ]",
        ),
        (
            "the denial shape must be absent — a denial exits 126 too",
            "*approval_denied*)",
        ),
        (
            "and the transport shape must be present",
            "*\"Sandbox initialization failed\"*)",
        ),
        (
            "and specifically the certificate — connection-refused is also a \
             transport failure at exit 126, so without this the whole block half \
             passes with nothing listening",
            "*\"invalid peer certificate\"*)",
        ),
        (
            "the private key is swept out of every READ grant, not just every write \
             grant (A04)",
            "select(.access | test(\"read\"))",
        ),
    ] {
        let hits = body.matches(needle).count();
        assert_eq!(
            hits, 1,
            "the smoke-tls recipe pins {why:?} in {hits} places (looked for \
             {needle:?}). Zero means the check is gone. More than one means the \
             needle is satisfied by something other than the check — a comment or an \
             echo — so it no longer pins it."
        );
    }
}

/// Every early **success** in `smoke-tls` is a skip, and each arm has to say so on
/// its own.
///
/// `exit 0` before the verification has run is the one outcome that reads exactly
/// like a pass in CI and in a terminal, so T10's rule is that it must announce
/// itself and name the command that fixes it. There are three such arms — no
/// `mkcert`, `mkcert` cannot issue, and the daemon's own T6 refusal — and a single
/// `body.contains("mkcert -install")` was satisfied by any one of them plus two
/// comments, so the remedy could be dropped from the arm task 7.2 is actually about
/// and nothing noticed.
///
/// So the window is per-arm: everything since the previous `exit`, which is where
/// the branch this one belongs to can start. Deleting the message from any single
/// arm reddens this, which is what a needle over the whole body could not do —
/// and the window is [`code_of`], comments removed, because with them in it the
/// mutation stayed green on a *comment* explaining that the refusal names
/// `mkcert -install`.
#[test]
fn every_early_success_in_the_squat_recipe_announces_itself_as_a_skip() {
    let body = code_of(&recipe("smoke-tls"));
    let mut arms = 0;
    let mut window = String::new();
    for line in body.lines() {
        window.push_str(line);
        window.push('\n');
        if !line.contains("exit ") {
            continue;
        }
        if line.trim() == "exit 0" {
            arms += 1;
            for (why, needle) in [
                (
                    "announce itself as a skip rather than reading like a pass",
                    "SKIPPED (not run, not passed)",
                ),
                ("name the command that fixes it (T10)", "mkcert -install"),
            ] {
                assert!(
                    window.contains(needle),
                    "the smoke-tls arm ending at this `exit 0` does not {why} \
                     (looked for {needle:?} since the previous exit):\n{window}"
                );
            }
        }
        window.clear();
    }
    assert_eq!(
        arms, 3,
        "smoke-tls has three skip arms — no mkcert, mkcert cannot issue, and the \
         daemon's own T6 refusal. Finding a different number means one was added \
         without a message or one was removed, and either way this test is no longer \
         checking what it says."
    );
}

/// `[ "$a" != "$b" ] && VAR=…` under `set -e` **exits the script** when the test is
/// false: the `&&` list returns the test's status, and there is no `else` to make it
/// a compound. It cost a full round trip in #32, in the recipe path least exercised
/// while developing — a normal checkout rather than a worktree — and every recipe
/// here runs `set -euo pipefail`.
///
/// So the shape is refused outright rather than remembered. `if … then VAR=…; fi` is
/// the same thing without the trap.
#[test]
fn no_recipe_gates_an_assignment_on_a_test_under_set_e() {
    for (number, line) in JUSTFILE.lines().enumerate() {
        let Some((test, rest)) = line.split_once("] &&") else {
            continue;
        };
        if !test.trim_start().starts_with('[') {
            continue;
        }
        let rest = rest.trim();
        let assignment = rest.split_once('=').is_some_and(|(name, _)| {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
        assert!(
            !assignment,
            "Justfile line {}: `[ … ] && VAR=…` takes the whole recipe down under \
             `set -e` whenever the test is false. Use `if … then VAR=…; fi`.\n  {line}",
            number + 1
        );
    }
}
