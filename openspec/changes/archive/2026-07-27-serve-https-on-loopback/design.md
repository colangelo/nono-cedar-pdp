# Design: serve-https-on-loopback

**The authoritative reasoning lives in
`docs/superpowers/specs/2026-07-26-https-on-loopback-design.md` (decisions T1–T11).** This
file records only what a reader of the change needs on the way past, and deliberately does
not restate it — two copies of an argument drift, and this repo has the scars.

| # | Decision | One-line reason |
|---|---|---|
| T1 | A TLS failure is `Err` ⇒ exit 126, not a recorded `Denied` | Upstream's shape; both closed, but they read differently in nono's audit |
| T2 | TLS opt-in; a broken `[tls]` refuses to serve | A silent HTTP fallback is worse than never having had TLS |
| T3 | `axum-server` 0.8 + `rustls`/`ring` | axum's `Listener::accept` has no `Result`; a hand-rolled handshake on the accept path serialises every approval |
| T4 | A readable private key is a refusal | OpenSSH's rule; not a proxy, so epic #1's "don't escalate a heuristic" does not apply |
| T5 | The URL names the literal `bind` address, never `localhost` | `localhost` resolves `::1` first, so a `[::1]` squatter silently intercepts a `127.0.0.1` deployment |
| T6 | Startup self-test through `rustls-platform-verifier`, **before** binding | Same crate ureq uses; testing after binding leaves a window where we serve untrusted |
| T7 | Certificates are minted, never generated on boot | An untrusted cert starts happily and denies everything — T2's failure by another route |
| T8 | Cert and key default under `~/.config/nono-cedar-pdp/tls/` | D13: home-anchored so the accidental case takes effort |
| T9 | `/healthz` says nothing new | #7 just finished removing disclosure here; the burden is on additions |
| T10 | The squat test drives real nono and **skips loudly** | A skip that reads like a pass stops being a verification |
| T11 | The TLS-layer test complements T10, never substitutes | Green tests agreeing with each other and disagreeing with nono is this repo's recurring failure |

## The two things most likely to be "fixed" wrong later

**Do not make the self-test connect to the real listener.** It reads as the obvious
simplification and it reintroduces the window T6 exists to close: a daemon that binds,
accepts, and *then* discovers its certificate is untrusted has already served. The
throwaway listener on `127.0.0.1:0` works because rustls verifies against the `ServerName`
the client is handed, not the socket it connected through — so asserting the name derived
from `bind` is a genuine test of the address we are about to serve on.

**Do not make a missing `[tls]` an error.** The shipped defaults must start without a
certificate ceremony, and `just serve-dev` must keep working. Plaintext is a documented
posture with a WARN, not a misconfiguration.

## Settled before implementation: IP SANs verify

Task 1, done first because T5 rested on it. Measured through
`Verifier::verify_server_cert` against an mkcert leaf with the CA installed:
`127.0.0.1`, `::1` and `localhost` all **accepted**; `127.0.0.2` and `example.com` both
rejected with `NotValidForName`. The negative rows are what make the positive ones mean
something — they prove the verifier is matching names rather than waving through anything
that chains to a trusted root. **T5 stands, no fallback needed.**

**Do not "verify" this with `security verify-cert`.** It reports a Certificate Transparency
failure for the same leaf *even with the CA in the System keychain*, and reports the
identical CT error for a name the certificate does not carry — so name matching is never
reached and the answer is uniformly wrong in a way that looks authoritative. The CLI
applies a CT policy the library path does not.

Same measurement confirms the two exemptions that make this workable: chains to a
user-added anchor escape both CT and the 398-day validity cap (the accepted leaf runs 27
months). That is why `mkcert -install` is a requirement, not a convenience.
