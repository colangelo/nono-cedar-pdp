default:
    @just --list

check:
    cargo check --all-targets

test:
    cargo test

lint: lint-paths
    cargo clippy --all-targets -- -D warnings

# Fail if a tracked file contains a real absolute home path
lint-paths:
    #!/usr/bin/env bash
    set -euo pipefail
    # Key on the RUNTIME home/username — a literal /Users/<name> in the checker
    # is itself the thing this forbids, and it only works on one machine.
    if git grep -nI -F -e "$HOME" -e "/Users/$(id -un)" -- . ; then
      echo "error: tracked file contains a real home path — use a relative path, \$HOME, or /Users/you" >&2
      exit 1
    fi

fmt:
    cargo fmt

serve config="./nono-cedar-pdp.toml":
    cargo run --release -- serve --config {{config}}

# Dev daemon: repo-relative policies + audit log, warns loudly, never a deployment.
serve-dev:
    cargo run -- serve --config ./nono-cedar-pdp.dev.toml

# Mint the locally-trusted TLS pair the [tls] block names; never overwrites.
mint-cert dir="~/.config/nono-cedar-pdp/tls":
    #!/usr/bin/env bash
    set -euo pipefail
    DIR='{{dir}}'
    DIR="${DIR/#\~/$HOME}"
    CERT="$DIR/cert.pem"
    KEY="$DIR/key.pem"
    command -v mkcert >/dev/null || {
      echo "FAIL: mkcert is not installed." >&2
      echo "  brew install mkcert && mkcert -install    # the second needs an admin password" >&2
      echo "  Or follow the openssl fallback in README.md — which needs the same admin" >&2
      echo "  step, because a leaf is only trusted through a CA that is a trust ANCHOR." >&2
      exit 1
    }
    # Never overwrite. The daemon may be serving this pair right now, the key file
    # is the only copy of the key, and the certificate may have been signed by the
    # operator's own CA rather than mkcert's — none of which this recipe can see.
    # Silently replacing it would read as success and take the listener down at the
    # next restart.
    for existing in "$CERT" "$KEY"; do
      if [ -e "$existing" ]; then
        echo "FAIL: $existing already exists; refusing to overwrite it." >&2
        echo "  Move it aside first, then re-run:" >&2
        echo "      mv \"$existing\" \"$existing.old\"" >&2
        exit 1
      fi
    done
    mkdir -p "$DIR"
    chmod 700 "$DIR"
    # TRUST_STORES=system is load-bearing, not tidiness: mkcert probes the Java
    # keystore on EVERY invocation and aborts before issuing anything when `keytool`
    # fails, which on a Mac without a JDK it does. Measured 2026-07-26 — without it
    # this recipe writes no certificate at all.
    #
    # All three loopback names, because the recipe cannot know which the operator
    # will bind: a certificate covering only 127.0.0.1 turns `bind = "[::1]:8181"`
    # into a daemon that refuses to start (T6), and that refusal arrives at the next
    # restart rather than here.
    TRUST_STORES=system mkcert -cert-file "$CERT" -key-file "$KEY" localhost 127.0.0.1 ::1
    # Set here rather than left to mkcert's choice: a private key other local users
    # can read is a refusal to serve (T4), so the recipe that mints it is where that
    # is settled. It defends against other local users only — never against the
    # sandboxed agent, which runs as the same uid; what keeps the key away from the
    # agent is its location relative to the profile's read grants.
    chmod 600 "$KEY"
    chmod 644 "$CERT"
    echo
    echo "cert: $CERT"
    echo "key:  $KEY  (0600 — other local users cannot read it)"
    echo
    echo "Add to nono-cedar-pdp.toml:"
    echo
    echo "    [tls]"
    echo "    cert = \"$CERT\""
    echo "    key  = \"$KEY\""
    echo
    echo "and point the nono profile at the LITERAL bind address, never a hostname:"
    echo
    echo '    "url": "https://127.0.0.1:8181/v1/approve"'
    echo
    echo '(`localhost` resolves ::1 before 127.0.0.1 on macOS, so a squatter on the'
    echo " other loopback address answers every localhost request. README.md has the"
    echo " long version, and what TLS does not buy.)"

# Copy the starter pack into policy_dir; never overwrites.
install-policies dir="~/.config/nono-cedar-pdp/policies":
    #!/usr/bin/env bash
    set -euo pipefail
    DIR='{{dir}}'
    DIR="${DIR/#\~/$HOME}"
    mkdir -p "$DIR"
    chmod 700 "$DIR"
    # Never overwrite — but never *silently* keep a stale copy either. The shipped pack
    # has already carried a wrong-allow fix once (the `git -c` hole), so an operator who
    # re-runs this after pulling must not be told "done" while their old policy stands.
    stale=0
    for src in policies/*.cedar; do
        dest="$DIR/$(basename "$src")"
        if [ ! -e "$dest" ]; then
            cp "$src" "$dest"
            echo "installed $(basename "$src")"
        elif cmp -s "$src" "$dest"; then
            echo "unchanged  $(basename "$src")"
        else
            echo "DIFFERS    $(basename "$src") — yours is not the shipped version"
            stale=$((stale + 1))
        fi
    done
    chmod 600 "$DIR"/*.cedar
    echo "policy_dir: $DIR"
    if [ "$stale" -gt 0 ]; then
        echo
        echo "$stale shipped polic(y/ies) differ from yours and were NOT overwritten."
        echo "Review before trusting them — a shipped fix may not be in your copy:"
        echo "  diff -u \"$DIR/<file>\" policies/<file>"
        exit 1
    fi

# End-to-end: a real `nono run` decision answered by Cedar.
smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    # The daemon's own state lives outside the repository on purpose (D13): the
    # smoke profile grants the sandboxed git read-write access to this tree, so a
    # policy dir here would be one the agent under test can rewrite.
    command -v nono >/dev/null || { echo "FAIL: nono is not installed"; exit 1; }
    command -v jq >/dev/null || { echo "FAIL: jq is not installed"; exit 1; }
    if curl -sf --max-time 2 http://127.0.0.1:8181/healthz >/dev/null 2>&1; then
      echo "FAIL: something already listens on 127.0.0.1:8181 — stop it first"; exit 1
    fi
    nono profile validate examples/cedar-pdp-smoke.json

    STATE="${XDG_CACHE_HOME:-$HOME/.cache}/nono-cedar-pdp/smoke"
    POLICIES="$STATE/policies"
    AUDIT="$STATE/decisions.jsonl"
    CONFIG="$STATE/nono-cedar-pdp.toml"
    mkdir -p "$POLICIES"
    chmod 700 "$STATE" "$POLICIES"
    cp policies/*.cedar "$POLICIES"/
    chmod 600 "$POLICIES"/*.cedar
    printf 'policy_dir = "%s"\naudit_log = "%s"\n\n[agents]\ncedar = "claude-code"\n' \
      "$POLICIES" "$AUDIT" > "$CONFIG"

    # In a git worktree `.git` is a pointer *file* and the real git directory lives
    # under the primary checkout, outside every grant this profile makes. git's own
    # repository discovery then fails with `fatal: not a git repository` and exit
    # 128 — *after* the PDP has already correctly returned allow — which reads as
    # the policy pack denying `git status` and is nothing of the kind (#32).
    # AGENTS.md tells agents to work in a `wt` worktree, so this is the default
    # path here rather than an edge case.
    #
    # One read grant on the common git directory covers both halves, since it
    # contains the per-worktree git directories. Deriving both paths from git and
    # comparing them is what keeps this a no-op in a normal checkout, where they are
    # the same directory.
    #
    # It has to go in the *profile*, not on the command line. `git` here runs in a
    # nested tool sandbox whose filesystem comes from the command policy, not from
    # the run's own grants (upstream v0.69.0, `crates/nono-cli/src/command_policy.rs`
    # — the sandbox spec at :676 and its `dedup_append` merge at :729). A run-level
    # `--read` duly appears in the capabilities banner and changes nothing for git,
    # which is a convincing-looking non-fix: measured, it still failed identically.
    PROFILE="$STATE/cedar-pdp-smoke.json"
    GIT_DIR_ABS=$(git rev-parse --absolute-git-dir 2>/dev/null || true)
    GIT_COMMON_ABS=""
    if [ -n "$GIT_DIR_ABS" ]; then
      COMMON=$(cd "$(git rev-parse --git-common-dir)" && pwd)
      # `[ … ] && VAR=…` would take the whole recipe down under `set -e` on the
      # normal-checkout path, where the test is false and the line returns non-zero.
      if [ "$GIT_DIR_ABS" != "$COMMON" ]; then
        GIT_COMMON_ABS="$COMMON"
      fi
    fi
    if [ -n "$GIT_COMMON_ABS" ]; then
      echo "--- worktree: granting the sandboxed git read-only access to $GIT_COMMON_ABS"
      # Read, deliberately not write. nono still reports one blocked write —
      # `<git-dir>/index.lock`, git refreshing its index — and `git status` exits 0
      # anyway, because that refresh is an optimisation git skips when it cannot
      # take the lock. Granting write to make the report tidy would put the
      # sandboxed agent inside the primary checkout's git database to buy nothing.
      #
      # Both places: the top-level read grant so the containment assertion below can
      # see it, and the git tool sandbox so git can actually resolve the repository.
      jq --arg p "$GIT_COMMON_ABS" \
        '.filesystem.read += [$p]
         | .command_policies.commands.git.from.session.sandbox.fs_read += [$p]' \
        examples/cedar-pdp-smoke.json > "$PROFILE"
    else
      cp examples/cedar-pdp-smoke.json "$PROFILE"
    fi

    # Every surface that grants *write* must be byte-identical to the shipped
    # profile. Asserted, not trusted: the generated profile is what the run uses, so
    # a jq edit that widened a write grant would hand the sandboxed agent the PDP's
    # own trust boundary — exactly what the containment check below exists to stop —
    # and read grants are the only thing a worktree needs.
    for surface in '.filesystem.allow' '.workdir.access' \
      '.command_policies.commands.git.from.session.sandbox.fs_write'; do
      if [ "$(jq -c "$surface" examples/cedar-pdp-smoke.json)" \
         != "$(jq -c "$surface" "$PROFILE")" ]; then
        echo "FAIL: the generated smoke profile changed a write surface ($surface)"; exit 1
      fi
    done

    # Assert the rule rather than asserting it in prose: no write grant in the
    # resolved profile may contain the policy dir or the audit log. This is the
    # same procedure the README gives an operator for their own profile. It reads
    # the *generated* profile, which is the one the run actually uses.
    nono profile validate "$PROFILE" >/dev/null
    echo "--- the profile's write grants must not reach the PDP's own state"
    for granted in $(nono profile show "$PROFILE" --format manifest \
      | jq -r '.filesystem.grants[] | select(.access | test("write")) | .path'); do
      for own in "$POLICIES" "$AUDIT"; do
        case "$own" in
          "$granted"|"$granted"/*)
            echo "FAIL: the profile grants write to $granted, which contains $own"; exit 1;;
        esac
      done
    done
    echo "OK: $POLICIES and $AUDIT are outside every write grant"

    cargo build --quiet
    ./target/debug/nono-cedar-pdp serve --config "$CONFIG" &
    PDP=$!
    trap 'kill $PDP 2>/dev/null || true' EXIT
    for _ in $(seq 1 40); do
      curl -sf --max-time 2 http://127.0.0.1:8181/healthz >/dev/null && break
      sleep 0.25
    done
    curl -sf --max-time 2 http://127.0.0.1:8181/healthz || { echo "FAIL: the PDP never became healthy"; exit 1; }
    echo
    LINES_BEFORE=$(wc -l < "$AUDIT" 2>/dev/null || echo 0)
    echo "--- expect ALLOW: git status"
    nono run --allow-cwd --profile "$PROFILE" -- git status >/dev/null
    echo "--- expect DENY: git push --force"
    if nono run --allow-cwd --profile "$PROFILE" -- git push --force >/dev/null 2>&1; then
      echo "FAIL: the force push was not blocked"; exit 1
    fi
    echo "--- decisions recorded in $AUDIT:"
    NEW=$(tail -n +$((LINES_BEFORE + 1)) "$AUDIT")
    echo "$NEW"
    echo "$NEW" | grep -q '"decision":"allow".*10-git:git-read-only' \
      || { echo "FAIL: no Cedar allow from 10-git:git-read-only"; exit 1; }
    echo "$NEW" | grep -q '"decision":"deny".*10-git:no-history-rewrites' \
      || { echo "FAIL: no Cedar deny from 10-git:no-history-rewrites"; exit 1; }
    # The upstream header contract, checked empirically — the one place it can be.
    # The decide endpoint requires `Content-Type: application/json`, and the `nono`
    # dev-dependency is the sandboxing library, so no unit test can observe what the
    # `nono-cli` webhook client actually sends (see tests/conformance.rs). Here a real
    # client sent the requests: had it stopped sending that content-type, both greps
    # above would already have failed with a 415 and no audit line at all, and this
    # line pins the other header, recorded verbatim as evidence on every decision.
    echo "$NEW" | grep -q '"user_agent":"nono-cli/' \
      || { echo "FAIL: the real webhook client did not present a nono-cli User-Agent — read crates/nono-cli/src/approval_runtime.rs, the header contract has changed"; exit 1; }
    echo "SMOKE PASSED"

# The squat test (T10): a real `nono run` blocked because the port is held by a
# process that does not have our key. Skips loudly without a local CA.
smoke-tls:
    #!/usr/bin/env bash
    set -euo pipefail
    # What this proves, and what `just smoke` cannot: nono's own webhook client
    # decides whether to believe whoever answers 127.0.0.1:8181, and it decides that
    # with the platform trust store. So the load-bearing run is not "our client
    # rejects an untrusted certificate" — this repo has repeatedly had green tests
    # that agreed with each other and disagreed with nono — it is a real `nono run`
    # against a real squatter, twice: once with this daemon holding the port (which
    # must be ALLOWED, or the negative half proves nothing) and once with a
    # keyless squatter holding it (which must be BLOCKED).
    command -v nono >/dev/null || { echo "FAIL: nono is not installed"; exit 1; }
    command -v jq >/dev/null || { echo "FAIL: jq is not installed"; exit 1; }
    command -v openssl >/dev/null || { echo "FAIL: openssl is not installed"; exit 1; }
    if ! command -v mkcert >/dev/null; then
      echo
      echo "  SKIPPED (not run, not passed): mkcert is not installed, so this machine"
      echo "  cannot mint a certificate nono will accept, and the ALLOW half of this"
      echo "  test — the half that gives the BLOCK half its meaning — cannot run."
      echo "      brew install mkcert && mkcert -install"
      echo
      exit 0
    fi
    if (exec 3<>/dev/tcp/127.0.0.1/8181) 2>/dev/null; then
      echo "FAIL: something already listens on 127.0.0.1:8181 — stop it first"; exit 1
    fi

    # Outside the repository for the same reason `just smoke` is (D13): this profile
    # grants the sandboxed git write access to the working tree, so the PDP's own
    # state — and now its private key — must not live in it.
    STATE="${XDG_CACHE_HOME:-$HOME/.cache}/nono-cedar-pdp/smoke-tls"
    POLICIES="$STATE/policies"
    AUDIT="$STATE/decisions.jsonl"
    CONFIG="$STATE/nono-cedar-pdp.toml"
    TLS="$STATE/tls"
    SQUAT="$STATE/squatter"
    mkdir -p "$POLICIES" "$TLS" "$SQUAT"
    chmod 700 "$STATE" "$POLICIES" "$TLS"
    cp policies/*.cedar "$POLICIES"/
    chmod 600 "$POLICIES"/*.cedar

    # A fresh pair every run, and the reason is the skip path below: verifying that
    # it works means running this recipe with `CAROOT` pointed at a throwaway
    # directory, which leaves behind a pair signed by a CA nothing trusts. Reusing
    # that would make this recipe skip for ever afterwards — a verification that
    # quietly stopped verifying, which is the exact failure T10 is about. Scoped to
    # the two files this recipe writes, under ~/.cache and never ~/.config.
    rm -f "$TLS/cert.pem" "$TLS/key.pem"
    # TRUST_STORES=system for the reason `mint-cert` gives: mkcert probes the Java
    # keystore on every invocation and aborts before issuing anything when `keytool`
    # fails.
    if ! TRUST_STORES=system mkcert -cert-file "$TLS/cert.pem" -key-file "$TLS/key.pem" \
         localhost 127.0.0.1 ::1 >/dev/null 2>&1; then
      echo
      echo "  SKIPPED (not run, not passed): mkcert could not mint a certificate."
      echo "      mkcert -install"
      echo
      exit 0
    fi
    chmod 600 "$TLS/key.pem"
    chmod 644 "$TLS/cert.pem"
    printf 'policy_dir = "%s"\naudit_log = "%s"\nbind = "127.0.0.1:8181"\n\n[agents]\ncedar = "claude-code"\n\n[tls]\ncert = "%s"\nkey = "%s"\n' \
      "$POLICIES" "$AUDIT" "$TLS/cert.pem" "$TLS/key.pem" > "$CONFIG"

    # `https` in the URL, and the LITERAL address rather than `localhost` (T5): on
    # macOS `localhost` resolves ::1 before 127.0.0.1, so a hostname here would let
    # a daemon on one loopback address and a squatter on the other both look
    # healthy while every request went to the squatter.
    #
    # The worktree grant is the same one `just smoke` carries and for the same
    # reason (#32): in a `wt` worktree `.git` is a pointer *file* and the real git
    # directory lives under the primary checkout, outside every grant this profile
    # makes, so git fails with `fatal: not a git repository` and exit 128 — after
    # the PDP has already correctly answered. It has to go in the command policy,
    # because an intercepted command's filesystem comes from there and NOT from the
    # run's own `--read` grants (upstream v0.69.0 `command_policy.rs`); a run-level
    # `--read` shows up in the capabilities banner and changes nothing, which is a
    # convincing-looking non-fix.
    PROFILE="$STATE/cedar-pdp-smoke-tls.json"
    URL="https://127.0.0.1:8181/v1/approve"
    GIT_DIR_ABS=$(git rev-parse --absolute-git-dir 2>/dev/null || true)
    GIT_COMMON_ABS=""
    if [ -n "$GIT_DIR_ABS" ]; then
      COMMON=$(cd "$(git rev-parse --git-common-dir)" && pwd)
      # `[ … ] && VAR=…` would take the whole recipe down under `set -e` on the
      # normal-checkout path, where the test is false and the line returns non-zero.
      if [ "$GIT_DIR_ABS" != "$COMMON" ]; then
        GIT_COMMON_ABS="$COMMON"
      fi
    fi
    if [ -n "$GIT_COMMON_ABS" ]; then
      echo "--- worktree: granting the sandboxed git read-only access to $GIT_COMMON_ABS"
      jq --arg p "$GIT_COMMON_ABS" --arg url "$URL" \
        '.command_policies.approval_backends.cedar.url = $url
         | .filesystem.read += [$p]
         | .command_policies.commands.git.from.session.sandbox.fs_read += [$p]' \
        examples/cedar-pdp-smoke.json > "$PROFILE"
    else
      jq --arg url "$URL" '.command_policies.approval_backends.cedar.url = $url' \
        examples/cedar-pdp-smoke.json > "$PROFILE"
    fi
    # Asserted, not trusted, exactly as in `just smoke`: a jq edit that widened a
    # write grant would hand the sandboxed agent the PDP's own trust boundary — and
    # now its private key, which is the whole control this recipe is testing.
    for surface in '.filesystem.allow' '.workdir.access' \
      '.command_policies.commands.git.from.session.sandbox.fs_write'; do
      if [ "$(jq -c "$surface" examples/cedar-pdp-smoke.json)" \
         != "$(jq -c "$surface" "$PROFILE")" ]; then
        echo "FAIL: the generated smoke profile changed a write surface ($surface)"; exit 1
      fi
    done
    nono profile validate "$PROFILE" >/dev/null
    echo "--- the profile's write grants must not reach the PDP's own state or key"
    for granted in $(nono profile show "$PROFILE" --format manifest \
      | jq -r '.filesystem.grants[] | select(.access | test("write")) | .path'); do
      for own in "$POLICIES" "$AUDIT" "$TLS"; do
        case "$own" in
          "$granted"|"$granted"/*)
            echo "FAIL: the profile grants write to $granted, which contains $own"; exit 1;;
        esac
      done
    done
    echo "OK: $POLICIES, $AUDIT and $TLS are outside every write grant"

    cargo build --quiet
    PDP=""
    SQUATTER=""
    trap 'if [ -n "$PDP" ]; then kill "$PDP" 2>/dev/null || true; fi
          if [ -n "$SQUATTER" ]; then kill "$SQUATTER" 2>/dev/null || true; fi' EXIT
    ./target/debug/nono-cedar-pdp serve --config "$CONFIG" > "$STATE/daemon.log" 2>&1 &
    PDP=$!
    READY=""
    for _ in $(seq 1 40); do
      # `-k`: this probe asks "is it up", not "is it trusted". Trust is what the
      # daemon's own startup self-test settled before it bound at all, and what the
      # ALLOW half below re-proves through nono's client rather than through curl's.
      if curl -sfk --max-time 2 https://127.0.0.1:8181/healthz >/dev/null 2>&1; then
        READY=1
        break
      fi
      if ! kill -0 "$PDP" 2>/dev/null; then break; fi
      sleep 0.25
    done
    if [ -z "$READY" ]; then
      # The daemon refuses to serve a certificate the platform verifier does not
      # accept (T6), and that refusal names `mkcert -install`. Reading it here is
      # what turns "no local CA" into a loud skip instead of a failure — and it is
      # measured through nono's own verifier rather than guessed at from the
      # keychain, because `security verify-cert` answers uniformly wrong (T7).
      if grep -q "was refused for" "$STATE/daemon.log" 2>/dev/null; then
        echo
        echo "  SKIPPED (not run, not passed): this machine's platform trust store"
        echo "  holds no local CA, so the daemon refused to serve the certificate"
        echo "  mkcert just minted — and nono would refuse it for the same reason."
        echo "      mkcert -install"
        echo
        echo "  Nothing here proves a squatter is blocked; only that we refuse to"
        echo "  serve something nono could not believe. The refusal in full:"
        echo
        sed -n 's/^/      /p' "$STATE/daemon.log"
        exit 0
      fi
      echo "FAIL: the PDP never became healthy over https"
      cat "$STATE/daemon.log"
      exit 1
    fi

    # ── The ALLOW half. Without it the BLOCK half proves nothing: a `nono run` that
    #    fails because nono never reached the port at all would satisfy it perfectly.
    #    This is also the only place anything proves nono's *own* client accepts this
    #    certificate — the daemon's self-test uses the same crate, but this is the
    #    binary.
    LINES_BEFORE=$(wc -l < "$AUDIT" 2>/dev/null || echo 0)
    echo
    echo "--- expect ALLOW over https: git status"
    nono run --allow-cwd --profile "$PROFILE" -- git status >/dev/null || {
      echo "FAIL: a command this pack allows was blocked while THIS daemon held the"
      echo "  port. If the error above says 'invalid HTTP version', the profile's URL"
      echo "  is http:// against an https listener — which is exactly the shape a"
      echo "  deployment takes when [tls] is configured and the profile is not, and"
      echo "  the daemon cannot see it: it never reads nono's URL."
      exit 1
    }
    NEW=$(tail -n +$((LINES_BEFORE + 1)) "$AUDIT")
    echo "$NEW" | grep -q '"decision":"allow".*10-git:git-read-only' \
      || { echo "FAIL: real nono did not get a Cedar allow over https"; echo "$NEW"; exit 1; }
    echo "OK: real nono completed the handshake and was answered by Cedar"

    # ── The BLOCK half. Same profile, same command; only the identity of whoever
    #    holds the port changes.
    kill "$PDP"
    wait "$PDP" 2>/dev/null || true
    PDP=""
    for _ in $(seq 1 40); do
      if (exec 3<>/dev/tcp/127.0.0.1/8181) 2>/dev/null; then sleep 0.25; else break; fi
    done
    # Self-signed, right names, right EKU, and a key that is not ours — which is the
    # only property that matters. openssl rather than mkcert deliberately: mkcert's
    # whole job is to be trusted, and a squatter is not.
    openssl req -x509 -newkey rsa:2048 -days 30 -nodes \
      -keyout "$SQUAT/key.pem" -out "$SQUAT/cert.pem" \
      -subj "/CN=nono-cedar-pdp squatter" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
      -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
    openssl s_server -accept 127.0.0.1:8181 -cert "$SQUAT/cert.pem" \
      -key "$SQUAT/key.pem" -quiet > "$STATE/squatter.log" 2>&1 &
    SQUATTER=$!
    HELD=""
    for _ in $(seq 1 40); do
      if (exec 3<>/dev/tcp/127.0.0.1/8181) 2>/dev/null; then HELD=1; break; fi
      sleep 0.25
    done
    [ -n "$HELD" ] || { echo "FAIL: the squatter never took the port"; cat "$STATE/squatter.log"; exit 1; }
    echo
    echo "--- expect BLOCKED: git status, with a squatter holding 127.0.0.1:8181"
    LINES_BEFORE=$(wc -l < "$AUDIT" 2>/dev/null || echo 0)
    set +e
    OUT=$(nono run --allow-cwd --profile "$PROFILE" -- git status 2>&1)
    CODE=$?
    set -e
    echo "$OUT" | sed -n 's/^/    /p'
    if [ "$CODE" -eq 0 ]; then
      echo "FAIL: the squatter's answer was accepted — this is the full bypass TLS exists to close"
      exit 1
    fi
    # 126 as a value, not "non-zero": upstream collapses BOTH blocking paths into
    # exit 126 (`handle_shim_stream` writes it for every `Err`), so the code alone
    # cannot tell a transport failure from a policy denial. The message is what
    # separates them, and getting the deny path here would mean nono had reached a
    # PDP — the opposite of what this asserts.
    if [ "$CODE" -ne 126 ]; then
      echo "FAIL: the command was blocked, but with exit $CODE rather than 126 —"
      echo "  that is not nono's shim-error path. Read handle_shim_stream in"
      echo "  crates/nono-cli/src/tool-sandbox/platform/macos.rs before changing this."
      exit 1
    fi
    case "$OUT" in
      *"Sandbox initialization failed"*) ;;
      *) echo "FAIL: exit 126, but not from a transport failure — expected nono's"
         echo "  Err(SandboxInit) text. This is T1: the block has to be the handshake"
         echo "  failing, not a decision anybody made."; exit 1;;
    esac
    # And specifically the *certificate*. Connection-refused is a transport failure
    # too, and it exits 126 with the same SandboxInit wrapper — so without this line
    # the whole BLOCK half would be satisfied by nothing listening at all, which
    # proves only that nono needs a PDP. The claim being tested is narrower and is
    # the entire point: something WAS listening, it answered the handshake, and nono
    # refused to believe it.
    case "$OUT" in
      *"invalid peer certificate"*) ;;
      *) echo "FAIL: blocked by a transport failure that was not the certificate."
         echo "  Connection-refused reads identically at exit-code level, so this"
         echo "  would otherwise pass with no squatter on the port at all."; exit 1;;
    esac
    case "$OUT" in
      *approval_denied*)
         echo "FAIL: this is a POLICY DENIAL, not a transport failure. Something"
         echo "  answered the webhook — a squatter that gets an answer through is"
         echo "  exactly the outcome this test exists to rule out."; exit 1;;
      *) ;;
    esac
    LINES_AFTER=$(wc -l < "$AUDIT" 2>/dev/null || echo 0)
    if [ "$LINES_AFTER" != "$LINES_BEFORE" ]; then
      echo "FAIL: this daemon recorded a decision while a squatter held the port"
      exit 1
    fi
    echo
    echo "OK: blocked by the transport path (exit 126, Err(SandboxInit)), not by a policy,"
    echo "    and no decision of ours was recorded — because we were never asked."
    echo "SMOKE-TLS PASSED"
