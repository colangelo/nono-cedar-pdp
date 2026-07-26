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

    # Assert the rule rather than asserting it in prose: no write grant in the
    # resolved profile may contain the policy dir or the audit log. This is the
    # same procedure the README gives an operator for their own profile.
    echo "--- the profile's write grants must not reach the PDP's own state"
    for granted in $(nono profile show examples/cedar-pdp-smoke.json --format manifest \
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
    nono run --allow-cwd --profile examples/cedar-pdp-smoke.json -- git status >/dev/null
    echo "--- expect DENY: git push --force"
    if nono run --allow-cwd --profile examples/cedar-pdp-smoke.json -- git push --force >/dev/null 2>&1; then
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
