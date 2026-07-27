# Tasks: serve-https-on-loopback

TDD throughout. `just test` must pass **both** full and filtered (`cargo test --lib config`,
`cargo test --lib isolation`). `just lint` clean. `just smoke` must still pass — it exercises
the plaintext path, which this change must leave untouched.

Every control below gets the **mutation gate**: delete the control, prove the test goes red
*for the right reason* (the regression, not a timeout or a panic), revert. Commit before
mutating, or the revert throws away real work.

## 1. Settle the IP SAN question first

Deliberately first: T5's URL rule rests on it, and building the config, the self-test and the
docs around an unmeasured assumption is how a spec hardens around a wrong fact.

- [x] 1.1 (**needed the operator**) `mkcert -install` — local CA created and installed in the System keychain
- [x] 1.2 Mint a leaf for `localhost 127.0.0.1 ::1`. Note `TRUST_STORES=system` is required: mkcert probes the Java keystore on every invocation and aborts before issuing when `keytool` fails
- [x] 1.3 **Measured through `rustls-platform-verifier` itself** — `127.0.0.1`, `::1`, `localhost` all accepted; `127.0.0.2` and `example.com` rejected `NotValidForName`. The negative rows prove the check is non-vacuous
- [x] 1.4 Not needed — T5 confirmed. Design doc §2/§7/§8 and the change design updated with the measurement
- [x] 1.5 **`security verify-cert` is disqualified as a check** and said so in both design docs: it reports a CT failure for the same leaf with the CA installed, *and* the identical error for a name the cert does not carry, so it never reaches name matching

## 2. Config surface

- [x] 2.1 Failing test: a config with no `[tls]` table loads and reports no TLS configured
- [x] 2.2 Failing test: `[tls]` with `cert` but no `key` (and the reverse) is a load error naming the missing key (T2)
- [x] 2.3 Failing test: an unknown key *inside* `[tls]` is a load error — the strictness rule must reach the nested table, which `deny_unknown_fields` does not give for free on a nested struct unless it is declared there too
- [x] 2.4 Failing test: `~/`-relative `cert` and `key` expand, like `policy_dir` does
- [x] 2.5 Implement: `Tls { cert, key }` as `Option<Tls>` on `Config`, `deny_unknown_fields`, `de_path` on both

## 3. Key protection

- [x] 3.1 Failing test: a group-readable key refuses to serve (T4)
- [x] 3.2 Failing test: a world-readable key refuses to serve
- [x] 3.3 Failing test: a key under an ancestor the existing walk rejects refuses to serve — reuse `isolation.rs`, do not reimplement the walk
- [x] 3.4 Failing test: a `0600` key owned by us passes
- [x] 3.5 Implement, resolving the pair at startup alongside the other state paths (D7) so the checked chain is the read chain
- [x] 3.6 Module docs state the scope honestly: **other local users only**, never the sandboxed agent (the house rule `tests/docs.rs` pins)
- [x] 3.7a (**remediation, 2026-07-27**) …and reaches `at_risk` on the trail, which was a
  separate claim with **no test at all**. Measured: deleting `warnings.extend(key_warnings)`
  from `serve` left all 272 tests green — the only assertion on `at_risk` anywhere asserted
  *false*, and the one through-the-binary key-in-cwd test uses the untrusted fixture, so the
  daemon refuses at the T6 self-test and never opens an audit log; the at-risk path was
  unreachable from it by construction. `a_tls_key_inside_the_working_directory_marks_the_audit_trail_at_risk`
  mints a **trusted** pair inside the cwd and lets the daemon serve, with `policy_dir` and
  `audit_log` outside it so the key's warning is the only one in play. Re-run of the
  mutation with it in place: red on `left: Bool(false)` with the SECURITY warning in the
  daemon's own log
- [x] 3.7 (**remediation, 2026-07-27**) The cwd containment warning reaches the key too. It covered `policy_dir` and `audit_log` and stopped there, so a key inside the working directory started silently — while module docs point 2 named that exact residual. `check_private_key` is now shaped like `check` (refuse + advisory `Vec<String>`); the warning names **read** grants, not write, because that is the grant kind that matters here and an operator drilled on the write rule would check the wrong column. It joins `at_risk`: an agent that can read the key answers approvals in our place and those approvals are in no trail of ours. Mutation: deleting the containment push reddens both the unit test and the through-the-binary one

## 4. The listener

Three things stage 3 left for this stage to carry rather than drop. Each is a live
test today; deleting one instead of repointing it removes a rule from the suite.

- **`a_tls_configured_daemon_refuses_rather_than_downgrade_to_plaintext`** (`tests/cli.rs`)
  is the *only* cover on T2's no-downgrade rule. It reads the transitional refusal that
  4.4 deletes. Repoint it at 4.2 — the claim in its name has to hold at both ends, and
  covered at neither is exactly how it was missed the first time.
- **`a_symlinked_tls_pair_is_resolved_before_serving`** (`tests/cli.rs`) pins D7 on the
  values `serve` holds, and reads them out of the same transitional message. Repoint it at
  whatever the listener logs or loads. Its sibling
  `a_symlinked_tls_key_is_checked_on_the_chain_it_resolves_to` is *not* a substitute and
  says so in its own docstring: it is satisfied by `isolation`'s internal `absolutize`.
- **`serve` logs the address it actually bound**, not the configured one, and
  `tests/cli.rs` reads the port back out of that line instead of guessing a free one. A
  TLS arm built on `axum_server::bind_rustls(addr, …)` binds internally and loses that,
  which would put every TLS test back on a guessed port; `from_tcp_rustls` over a listener
  bound here keeps it.

- [x] 4.1 Failing test (T11): our own rustls client, configured like nono's, completes a handshake against a TLS-configured daemon and gets a real decision back
- [x] 4.2 Failing test: a TLS-configured daemon does **not** answer a plaintext request — the no-silent-downgrade rule, asserted from the client side
- [x] 4.3 Failing test: an unreadable / unparseable / mismatched cert-key pair exits non-zero without binding (T2)
- [x] 4.3a (**remediation, 2026-07-27**) Those tests asserted only that *some* `[tls]` refusal happened, and three of them use the untrusted openssl fixture — so the T6 self-test, standing right behind them, satisfied every assertion. Measured: making the "mismatched" pair MATCH, and deleting the `chmod 000`, both left their tests green, as did replacing `load_pair`'s cert-read arm with `unwrap_or_default()`. Each now pins its own arm's message. Same shape one level down in 5.1's bind-address sibling: its `contains(addr.ip())` was satisfied by `main`'s `serving on {bind}:` wrapper, so dropping `{ip}` from the self-test message left it green. And `load_pair`'s three **key** arms had no test at all — every case above fails on the certificate or the pairing — so they have one now, all three mutation-proven
- [x] 4.4 Implement: `axum-server` arm in `server::serve`; the router is untouched so existing `tests/server.rs` coverage carries over
- [x] 4.5 Confirm every pre-existing `tests/server.rs` case still passes over plaintext — this change must be invisible to the default posture
- [x] 4.6 Plaintext startup logs the impersonation WARN; assert on it rather than trusting it exists
- [x] 4.7 The https arm reports the address it bound, like the plaintext one does, and the TLS tests take an ephemeral port through it rather than guessing one

## 5. The startup self-test

- [x] 5.1 Failing test: a daemon whose certificate is untrusted exits non-zero (T6)
- [x] 5.2 Failing test: **nothing is ever accepted on the bind address** in that case — the window is the whole point, so assert the port is not listening, not merely that the process exited
- [x] 5.3 Implement: throwaway listener on `127.0.0.1:0`, `rustls-platform-verifier` client, `ServerName` derived from `bind`, all **before** the real bind
- [x] 5.4 Mutation: **run twice, 2026-07-27.** (a) Ordering — With the call moved below the bind, 5.2 goes red on the daemon's own `listening bind=127.0.0.1:62571` line and 5.1 goes red on `Address already in use` — while the exit code stays non-zero in both, which is exactly why neither test settles for asserting that. Reverted; suite green. (b) `ServerName` — hardcoding `127.0.0.1` in place of the value derived from `bind` reddens `a_daemon_on_the_ipv6_loopback_serves_a_certificate_minted_for_only_that_address` with `NotValidForName`, and **nothing else**: the "does not cover the bind address" case has both addresses wrong for each other, so it stays green under it. That asymmetry was measured, not assumed, and is why the two tests are separate

## 6. Minting and the operator path

- [x] 6.1 `just mint-cert` — mkcert for `localhost 127.0.0.1 ::1`, `0600` key and `0644` cert, `0700` directory, defaulting to `~/.config/nono-cedar-pdp/tls/` and taking a path so a test can run it. It **refuses to overwrite** an existing pair: the daemon may be serving it, the file is the only copy of the key, and the certificate may be from the operator's own CA. `tests/cli.rs` runs the recipe and hands the result to the real daemon over https, which is the only assertion that cannot pass by coincidence. Mutation, four ways: dropping `chmod 700`, dropping `TRUST_STORES=system` (mkcert aborts on the keytool probe), dropping `::1` from the names, and dropping the overwrite guard each redden it for their own reason. Measured and recorded in the test: mkcert sets `0600`/`0644` itself regardless of umask, so the recipe's own `chmod` lines pin nothing today and are there for the day that changes
- [x] 6.2 An `openssl` fallback in the README — CA, leaf, and the `security add-trusted-cert` step, since a bare self-signed leaf is not an anchor. **Run rather than read**: `tests/docs.rs` executes the block into a temp dir and puts its leaf in front of a real webpki verifier for all three loopback names, with `example.com` as the negative row. Mutations: removing an address from `subjectAltName` reddens it (`NotValidForName`), naming a *different* EKU reddens it ("does not allow extended key usage for server authentication") — and removing the `extendedKeyUsage` line altogether does **not**, because an absent EKU is unrestricted. That last one corrected the block's own comment, which claimed otherwise, and is held by a README needle instead
- [x] 6.2a (**remediation, 2026-07-27**) The fallback block was **run** and two things it
  did were wrong. It `cd`'d into `$TLS_DIR` and minted the local **CA key** there, so
  `ca-key.pem` landed in the directory the `[tls]` block names — eight lines above prose
  saying that key "belongs nowhere near the daemon" — which made A04's read-grant residual
  on that tree yield a CA key good for *any name this machine trusts*, strictly wider than
  A04 states. And it overwrote an existing pair in silence while `just mint-cert` refuses
  and has a test pinning the refusal; measured, a sentinel `key.pem` was replaced and the
  block exited 0. Now: a separate `$CA_DIR` (CSR and serial with it), an overwrite guard on
  all three files each proven on its own run, and the whole thing a subshell so `set -e`
  and that refusal cannot take a pasting operator's shell down. `tests/docs.rs` asserts
  `$TLS_DIR` holds `cert.pem` and `key.pem` and **nothing else** — the whole set, because a
  leftover CSR beside the daemon is the same mistake made smaller — and the
  `security add-trusted-cert` step, the one part no test can run for real, is now **run
  with `sudo` and `security` shimmed onto `PATH`** — which immediately caught a defect the
  subshell had just introduced: the two directory variables were assigned *inside* it, so
  the anchor step, a separate command, ran on `/ca.pem` and would have trusted nothing
  after asking for an admin password. They are exported outside the subshell now. The test
  sets neither variable and overrides `HOME` instead, because an environment that already
  carries them is an environment in which this defect is invisible
- [x] 6.3 README §"Serving https on loopback": the `[tls]` block, the refusal list, the literal-address URL rule with the `::1`-before-`127.0.0.1` reason and what it costs (every `localhost` request reaches the squatter), and the CT/user-anchor note including why `security verify-cert` cannot answer the question. Each pinned by its own needle in `tests/docs.rs`
- [x] 6.4 README §"What TLS does not buy", in the register's voice and cross-linked to it: same-uid key readers, nono's identity, availability, and the fourth one that only shows up end-to-end — a caught squatter produces no record of ours, because we were never asked. `## Security posture` no longer calls TLS "the first follow-up"

## 7. The squat test

- [x] 7.1 `just smoke-tls`, run for real 2026-07-27. Two halves against the same profile and command, changing only who holds `127.0.0.1:8181`: with this daemon there, real nono completes the handshake and Cedar answers (`"decision":"allow"` from `10-git:git-read-only`) — the half that gives the other one meaning, and the only place anything proves nono's own *binary* accepts our certificate; with a keyless openssl `s_server` there, the command is blocked. Mutating the profile URL to `http://` reddens the ALLOW half (`protocol: http parse fail: invalid HTTP version`), so it is not vacuous
- [x] 7.2 The skip is **measured through the daemon's own T6 refusal**, not guessed at from the keychain — `security verify-cert` answers uniformly wrong (T7), and the refusal already names `mkcert -install`. Verified by running `CAROOT=$(mktemp -d) just smoke-tls`: it prints the refusal in full, names `mkcert -install`, and exits **0**. And the pair is re-minted every run, because that verification leaves a pair behind signed by a CA nothing trusts — reusing it would make the recipe skip for ever, which is the failure T10 is about. Confirmed: the next ordinary run recovers and passes
- [x] 7.3 **Exit 126 alone does not distinguish them** — read at the source rather than assumed: upstream's `handle_shim_stream` writes 126 for *every* `Err`, so `Err(BlockedCommand)` from a policy denial and `Err(SandboxInit)` from a transport failure share it. So the recipe asserts the code *and* the message: `Sandbox initialization failed` present, `approval_denied` absent, `invalid peer certificate` present, and no new line in our own audit log. That third one has teeth — swapping the squatter for a plaintext `python3 -m http.server` reddens it (`received corrupt message of type InvalidContentType`), which is what stops connection-refused, or nothing listening at all, from satisfying the whole BLOCK half
- [x] 7.3a (**remediation, 2026-07-27**) The guards on 7.2 and 7.3 were satisfied by the
  *prose around* the checks. `"126"` matched four comments and echoes as well as the `if`,
  so deleting the whole `[ "$CODE" -ne 126 ]` block left the test green (recipe still
  parses, `just --dry-run smoke-tls` → 0); `"mkcert -install"` matched four places, so the
  remedy could be dropped from the T6 arm — the one 7.2 is about. Needles are now the
  assertion's own syntax, matched **exactly once**, against a comment-stripped body, and
  the skip is a separate per-arm test: every `exit 0` must announce "SKIPPED (not run, not
  passed)" and name `mkcert -install` within its own arm. The first version of that test
  still passed the mutation — the window held a *comment* saying the refusal "names
  `mkcert -install`" — which is why `code_of` exists. Eight README needles were vacuous the
  same way (`"is not a substitute"` also matched a sentence about the cwd warning eight
  sections down), so exactly-once is now the rule there too, and it immediately caught a
  needle the read-sweep commit itself made ambiguous
- [x] 7.3b (**remediation, 2026-07-27**) The profile sweep sweeps **read** as well. It
  folded the TLS directory into the existing *write* loop, while the jq edit it exists to
  police is itself a read-grant edit and read is the grant kind that hands the private key
  over whole (A04). Measured against a profile granting read on the recipe's own TLS
  directory under `~/.cache`: the shipped write sweep caught nothing, the new read sweep
  catches it. The comment claiming the write sweep covered the key is corrected, and the
  README's operator procedure — which had the identical hole, being write-only — now
  carries the read half, since that is where an operator gets the command for their own
  profile. `just smoke-tls` re-run end to end: both sweeps pass, ALLOW and BLOCK halves
  unchanged
- [x] 7.4 The worktree grant goes into the **command policy** (`commands.git.from.session.sandbox.fs_read`) as well as the top-level read, exactly as `just smoke` does, with the reason in the recipe. Proven by the run: it passed from this worktree, where a run-level `--read` alone fails identically-looking
- [x] 7.5 The shape is now **refused by a test** rather than remembered: `no_recipe_gates_an_assignment_on_a_test_under_set_e` scans every Justfile line for `[ … ] && NAME=…`. Every readiness and wait loop in the new recipe uses `if … then … fi` for the same reason

## 8. Documentation and close-out

- [x] 8.1 Design §10 ticked and pointed at the T1–T11 doc, with the two limits stated beside the tick rather than under it. §2's impersonation note gets a correction trail: it said nono "denies" a failed handshake, and nono *blocks* — a reader inheriting that word looks for a deny reason that is never there
- [x] 8.2 A02 revisited rather than edited: it listed #5 and #13 together under "what would close it", and they close different directions — #5 closed the outbound one, A02 *is* the inbound one and is untouched. The residual TLS introduces is filed separately as **A04** (same-uid key readers; the mirror of D13, where the dangerous grant is write and here it is **read**), so that "we fixed #5" cannot come to read as "A02 is smaller now"
- [x] 8.3 `openspec validate --changes serve-https-on-loopback` — passes (2026-07-27)
- [x] 8.2a (**remediation, 2026-07-27**) A04 records the two things it assumed of the
  artifacts that were not true — the write-only profile procedure it leans on, and the CA
  key minted into the daemon's own directory — rather than being quietly corrected
- [x] 8.4 Re-run after the stage-3 remediation (2026-07-27): `just test` green — 170 lib +
  33 `cli` + 5 conformance + 10 `docs` + 14 `policies` + 1 `public_api` + 45 `server`;
  filtered green too (`--lib config` 12, `--lib isolation` 36, `--test cli tls` 12,
  `--test docs squat` 2, `--test docs fallback` 2, `--test docs anchor` 1,
  `--test cli at_risk` 1); `just lint`
  clean; `just smoke` still passes over plaintext, which is the check that this change
  stayed invisible to the default posture; and `just smoke-tls` passes end to end,
  including the new read sweep. Re-run at close-out if anything lands after this
- [ ] 8.5 Push to `internal` **and** `origin`; close #5 with the evidence, including the measured IP SAN result from task 1
