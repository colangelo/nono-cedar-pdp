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
- [x] 4.4 Implement: `axum-server` arm in `server::serve`; the router is untouched so existing `tests/server.rs` coverage carries over
- [x] 4.5 Confirm every pre-existing `tests/server.rs` case still passes over plaintext — this change must be invisible to the default posture
- [x] 4.6 Plaintext startup logs the impersonation WARN; assert on it rather than trusting it exists
- [x] 4.7 The https arm reports the address it bound, like the plaintext one does, and the TLS tests take an ephemeral port through it rather than guessing one

## 5. The startup self-test

- [x] 5.1 Failing test: a daemon whose certificate is untrusted exits non-zero (T6)
- [x] 5.2 Failing test: **nothing is ever accepted on the bind address** in that case — the window is the whole point, so assert the port is not listening, not merely that the process exited
- [x] 5.3 Implement: throwaway listener on `127.0.0.1:0`, `rustls-platform-verifier` client, `ServerName` derived from `bind`, all **before** the real bind
- [ ] 5.4 Mutation: move the self-test after the bind and prove 5.2 goes red — this is the one that catches the "obvious simplification" the design warns about

## 6. Minting and the operator path

- [ ] 6.1 `just mint-cert` — mkcert for `localhost 127.0.0.1 ::1`, writing `0600` key and `0644` cert under `~/.config/nono-cedar-pdp/tls/`
- [ ] 6.2 An `openssl` fallback recipe in the README for operators without mkcert, including the `serverAuth` EKU and all three SANs
- [ ] 6.3 README: the `[tls]` block, the **literal-address URL rule** with the resolver-order reason, and the CT/user-anchor note explaining why a bare self-signed leaf is not a substitute
- [ ] 6.4 README: what TLS does not buy — same-uid code that can read the key, nono's identity, availability — in the register's existing voice

## 7. The squat test

- [ ] 7.1 `just smoke-tls`: bind the port with a keyless self-signed cert, run a real intercepted command under `nono run`, assert it is **blocked**
- [ ] 7.2 Detect a missing CA and **skip loudly** with a message naming `mkcert -install` (T10) — verify the skip path by running it with the CA absent
- [ ] 7.3 Assert the block is nono's transport-error path (exit 126), not a policy denial — T1's distinction, and the thing a future reader will get wrong
- [ ] 7.4 Beware the trap from #32: run-level `nono run --read` grants do **not** extend to nested tool sandboxes; an intercepted command's filesystem comes from the command policy
- [ ] 7.5 Beware `set -euo pipefail` + `[ "$a" != "$b" ] && VAR=…` in the recipe — false test exits the script (the #32 trap)

## 8. Documentation and close-out

- [ ] 8.1 Design §10: mark https-on-loopback done, pointing at the new design doc
- [ ] 8.2 `docs/audits/`: revisit the impersonation entry — what is now closed, and what remains accepted (same-uid key readers)
- [ ] 8.3 `openspec validate --changes serve-https-on-loopback`
- [ ] 8.4 `just test` full **and** filtered; `just lint`; `just smoke`
- [ ] 8.5 Push to `internal` **and** `origin`; close #5 with the evidence, including the measured IP SAN result from task 1
