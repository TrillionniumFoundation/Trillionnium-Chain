#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

CARGO_BIN="$(command -v cargo || true)"
if [[ -z "$CARGO_BIN" ]]; then
  echo "[FAIL] cargo not found" >&2
  exit 127
fi

"$CARGO_BIN" build --locked -q -p trnm-cli
CLI="$ROOT/trillionnium/target/debug/trnm-cli"
[[ -x "$CLI" ]] || { echo "[FAIL] current trnm-cli artifact missing: $CLI" >&2; exit 2; }

tx_help="$($CLI tx --help)"
for command in submit-consumption-receipt challenge-consumption resolve-consumption; do
  if ! grep -Eq "^  ${command}([[:space:]]|$)" <<<"$tx_help"; then
    echo "[FAIL] active PoCO tx command missing from command table: $command" >&2
    exit 3
  fi
  if ! "$CLI" tx "$command" --help >/dev/null 2>&1; then
    echo "[FAIL] active PoCO tx command is not invocable: $command" >&2
    exit 3
  fi
done
for retired in commit-result reveal-result; do
  if grep -Fq -- "$retired" <<<"$tx_help"; then
    echo "[FAIL] retired worker tx command leaked into active help: $retired" >&2
    exit 4
  fi
done

TMP_DIR="$(mktemp -d /tmp/trnm-poco-cli-cutover.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT
mkdir -p "$TMP_DIR/home"
if ! initial_dirs="$(find "$TMP_DIR" -type d -print | LC_ALL=C sort)"; then
  echo "[FAIL] unable to capture initial cutover sandbox directories" >&2
  exit 8
fi

set +e
commit_out=$(HOME="$TMP_DIR/home" TRNM_WALLET_STORE="$TMP_DIR/wallets" \
  TRNM_RPC_TX_FILE="$TMP_DIR/txs.json" \
  "$CLI" tx commit-result 999 worker1 \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 999 2>&1)
commit_rc=$?
reveal_out=$(HOME="$TMP_DIR/home" TRNM_WALLET_STORE="$TMP_DIR/wallets" \
  TRNM_RPC_TX_FILE="$TMP_DIR/txs.json" \
  "$CLI" tx reveal-result 999 \
  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 2>&1)
reveal_rc=$?
set -e

if [[ "$commit_rc" -eq 0 || "$reveal_rc" -eq 0 ]]; then
  echo "[FAIL] retired worker tx command unexpectedly succeeded: commit_rc=$commit_rc reveal_rc=$reveal_rc" >&2
  exit 5
fi
if ! grep -Fq -- '`trnm-cli tx commit-result` is retired from the active CLI surface' <<<"$commit_out"; then
  echo "[FAIL] commit-result retirement notice missing" >&2
  exit 6
fi
if ! grep -Fq -- '`trnm-cli tx reveal-result` is retired from the active CLI surface' <<<"$reveal_out"; then
  echo "[FAIL] reveal-result retirement notice missing" >&2
  exit 7
fi
if ! state_files="$(find "$TMP_DIR" -type f -print)"; then
  echo "[FAIL] unable to inspect retired-command side effects" >&2
  exit 8
fi
if [[ -n "$state_files" ]]; then
  echo "[FAIL] retired tx command wrote local state" >&2
  printf '%s\n' "$state_files" >&2
  exit 8
fi
if ! state_dirs="$(find "$TMP_DIR" -type d -print | LC_ALL=C sort)"; then
  echo "[FAIL] unable to inspect retired-command directory side effects" >&2
  exit 8
fi
if [[ "$state_dirs" != "$initial_dirs" ]]; then
  echo "[FAIL] retired tx command changed local directory state" >&2
  printf '%s\n' "$state_dirs" >&2
  exit 8
fi

echo "[OK] active PoCO CLI cutover gate passed; legacy worker tx surface remains retired"
