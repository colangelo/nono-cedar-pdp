default:
    @just --list

check:
    cargo check --all-targets

test:
    cargo test

lint:
    cargo clippy --all-targets -- -D warnings

fmt:
    cargo fmt

serve config="./nono-cedar-pdp.toml":
    cargo run --release -- serve --config {{config}}

# End-to-end: a real `nono run` decision answered by Cedar.
smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v nono >/dev/null || { echo "FAIL: nono is not installed"; exit 1; }
    if curl -sf --max-time 2 http://127.0.0.1:8181/healthz >/dev/null 2>&1; then
      echo "FAIL: something already listens on 127.0.0.1:8181 — stop it first"; exit 1
    fi
    nono profile validate examples/cedar-pdp-smoke.json
    cargo build --quiet
    ./target/debug/nono-cedar-pdp serve --config ./nono-cedar-pdp.toml &
    PDP=$!
    trap 'kill $PDP 2>/dev/null || true' EXIT
    for _ in $(seq 1 40); do
      curl -sf --max-time 2 http://127.0.0.1:8181/healthz >/dev/null && break
      sleep 0.25
    done
    curl -sf --max-time 2 http://127.0.0.1:8181/healthz || { echo "FAIL: the PDP never became healthy"; exit 1; }
    echo
    LINES_BEFORE=$(wc -l < ./decisions.jsonl 2>/dev/null || echo 0)
    echo "--- expect ALLOW: git status"
    nono run --allow-cwd --profile examples/cedar-pdp-smoke.json -- git status >/dev/null
    echo "--- expect DENY: git push --force"
    if nono run --allow-cwd --profile examples/cedar-pdp-smoke.json -- git push --force >/dev/null 2>&1; then
      echo "FAIL: the force push was not blocked"; exit 1
    fi
    echo "--- decisions recorded:"
    NEW=$(tail -n +$((LINES_BEFORE + 1)) ./decisions.jsonl)
    echo "$NEW"
    echo "$NEW" | grep -q '"decision":"allow".*10-git:git-read-only' \
      || { echo "FAIL: no Cedar allow from 10-git:git-read-only"; exit 1; }
    echo "$NEW" | grep -q '"decision":"deny".*10-git:no-history-rewrites' \
      || { echo "FAIL: no Cedar deny from 10-git:no-history-rewrites"; exit 1; }
    echo "SMOKE PASSED"
