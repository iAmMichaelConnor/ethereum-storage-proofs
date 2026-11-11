#!/usr/bin/env bash
# Runs the ethereum_oracle_tests package against the reference oracle: starts the
# oracle server, waits until it answers, runs the tests and stops the server.
# Needs `npm ci --prefix tests/ethereum_oracle_tests`; extra arguments go to
# `nargo test`, and $NARGO selects the nargo binary.
set -euo pipefail
cd "$(dirname "$0")/../.."
port=8095
node tests/ethereum_oracle_tests/oracle_server.mjs "$port" &
server=$!
trap 'kill "$server"' EXIT
for _ in $(seq 100); do
  curl -sf "http://127.0.0.1:$port/health" > /dev/null && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$port/health" > /dev/null || { echo "oracle server did not start" >&2; exit 1; }
"${NARGO:-nargo}" --program-dir tests/ethereum_oracle_tests test --force-brillig --inliner-aggressiveness 0 \
  --test-threads 4 --oracle-resolver "http://127.0.0.1:$port" "$@"
