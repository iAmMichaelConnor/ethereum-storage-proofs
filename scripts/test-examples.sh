#!/usr/bin/env bash
# Run the example contracts' tests against a local TXE. The tests run the examples' logic in TXE test contexts; no
# contract is compiled or deployed. TXE makes no proofs and sends no network transactions.
#
#   ./scripts/test-examples.sh [--jobs N] [example...]
#
# Examples are directory names under examples/ (default: all of them). --jobs N (default: the number of cores) is
# passed to `nargo test` as --test-threads. Environment: TXE_PORT (default 8081), NARGO (default aztec-nargo).
set -euo pipefail

NARGO=${NARGO:-aztec-nargo}
PORT=${TXE_PORT:-8081}
jobs=$(nproc)
examples=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --jobs) jobs="$2"; shift 2 ;;
        --jobs=*) jobs="${1#--jobs=}"; shift ;;
        -*) echo "Unknown option: $1" >&2; exit 2 ;;
        *) examples+=("$1"); shift ;;
    esac
done

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/examples"
if [[ ${#examples[@]} -eq 0 ]]; then
    for dir in */; do [[ -f "$dir/contract/Nargo.toml" ]] && examples+=("${dir%/}"); done
fi

# The packages with tests.
packages=()
for example in "${examples[@]}"; do
    [[ -d "$example" ]] || { echo "No example named $example" >&2; exit 2; }
    for manifest in "$example"/*/Nargo.toml; do
        if grep -rq '#\[test' "$(dirname "$manifest")/src"; then
            packages+=("$(sed -n 's/^name = "\(.*\)"$/\1/p' "$manifest")")
        fi
    done
done

mkdir -p target
LOG_LEVEL="${LOG_LEVEL:-error}" aztec start --txe --port "$PORT" > "target/txe-$PORT.log" 2>&1 &
txe_pid=$!
trap 'kill $txe_pid 2>/dev/null || true' EXIT
until nc -z 127.0.0.1 "$PORT" 2>/dev/null; do
    kill -0 $txe_pid 2>/dev/null || { echo "TXE failed to start; see examples/target/txe-$PORT.log" >&2; exit 1; }
    sleep 0.5
done

export NARGO_FOREIGN_CALL_TIMEOUT=300000
status=0
for package in "${packages[@]}"; do
    "$NARGO" test --package "$package" --silence-warnings --test-threads "$jobs" \
        --oracle-resolver "http://127.0.0.1:$PORT" || status=1
done
exit $status
