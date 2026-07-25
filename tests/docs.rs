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
        // The raw-path caveat.
        ("endpoint paths arrive raw", "denied outright"),
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
