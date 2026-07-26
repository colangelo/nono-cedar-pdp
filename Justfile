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
