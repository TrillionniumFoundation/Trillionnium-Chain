#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TX_CLI="${TRNM_TX_CLI:-trnm-cli}"
REQUIRE_REAL_TX_CLI="${REQUIRE_REAL_TX_CLI:-0}"
OUT_DIR="${OUT_DIR:-$ROOT/data/worker-cli-readiness}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT="$OUT_DIR/worker-real-cli-readiness-$TS.md"

status="NOT_READY"
reason=""
cmd_exists="no"
supports_tx="no"
commit_ok="no"
query_ok="no"
query_hash_match="no"
query_status=""
commit_tx_hash=""

extract_tx_hash() {
  local raw="$1"
  local h
  h=$(printf "%s\n" "$raw" | sed -n 's/.*tx_hash[[:space:]]*[:=][[:space:]]*\([0-9A-Fa-f]\{16,128\}\).*/\1/p' | head -n1 || true)
  if [[ -z "$h" ]]; then
    h=$(printf "%s\n" "$raw" | sed -n 's/.*txhash[[:space:]]*[:=][[:space:]]*\([0-9A-Fa-f]\{16,128\}\).*/\1/p' | head -n1 || true)
  fi
  printf "%s" "$h"
}

extract_query_status() {
  local raw="$1"
  local s
  s=$(printf "%s\n" "$raw" | sed -n 's/^status[[:space:]]*[:=][[:space:]]*\([^[:space:]]*\).*/\1/p' | head -n1 || true)
  if [[ -z "$s" ]]; then
    s=$(printf "%s\n" "$raw" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
  fi
  printf "%s" "$s"
}

if command -v "$TX_CLI" >/dev/null 2>&1; then
  cmd_exists="yes"
  if "$TX_CLI" tx --help >/dev/null 2>&1; then
    supports_tx="yes"

    # Minimal tx lifecycle proof: submit commit-result, then query by tx_hash.
    task_id="${TRNM_REALCLI_PROBE_TASK_ID:-9999991}"
    worker="${TRNM_REALCLI_PROBE_WORKER:-worker_readiness}"
    commit_hash="${TRNM_REALCLI_PROBE_COMMIT_HASH:-$(printf 'a%.0s' {1..64})}"
    nonce="${TRNM_REALCLI_PROBE_NONCE:-1}"

    set +e
    commit_out=$("$TX_CLI" tx commit-result "$task_id" "$worker" "$commit_hash" "$nonce" 2>&1)
    commit_rc=$?
    set -e

    if [[ $commit_rc -eq 0 ]]; then
      commit_tx_hash="$(extract_tx_hash "$commit_out")"
      if [[ "$commit_tx_hash" =~ ^[0-9A-Fa-f]{16,128}$ ]]; then
        commit_ok="yes"

        set +e
        query_out=$("$TX_CLI" tx query "$commit_tx_hash" 2>&1)
        query_rc=$?
        set -e

        if [[ $query_rc -eq 0 ]]; then
          query_ok="yes"
          query_seen_hash="$(extract_tx_hash "$query_out")"
          query_status="$(extract_query_status "$query_out")"
          commit_tx_hash_lc="$(printf "%s" "$commit_tx_hash" | tr '[:upper:]' '[:lower:]')"
          query_seen_hash_lc="$(printf "%s" "$query_seen_hash" | tr '[:upper:]' '[:lower:]')"
          if [[ -n "$query_seen_hash" && "$query_seen_hash_lc" == "$commit_tx_hash_lc" ]]; then
            query_hash_match="yes"
          fi
          if [[ "$query_hash_match" == "yes" && -n "$query_status" ]]; then
            status="READY"
            reason="tx lifecycle verified (commit + query visible)"
          else
            reason="tx query output missing required fields (hash/status consistency)"
          fi
        else
          reason="tx query failed for submitted tx_hash=$commit_tx_hash"
        fi
      else
        reason="commit-result output missing valid tx_hash"
      fi
    else
      reason="commit-result failed during readiness probe"
    fi
  else
    reason="tx subcommand missing: '$TX_CLI tx --help' failed"
  fi
else
  reason="tx cli not found in PATH: $TX_CLI"
fi

cat > "$REPORT" <<EOF
# Worker Real CLI Readiness

- ts: \
  $(date '+%F %T %Z')
- tx_cli: \
  \
  \
  $TX_CLI
- status: **$status**
- reason: $reason

## Checks
- command exists: $cmd_exists
- supports \`tx\` subcommand: $supports_tx
- probe commit-result success: $commit_ok
- probe commit tx_hash: ${commit_tx_hash:-N/A}
- probe query success: $query_ok
- probe query hash match: $query_hash_match
- probe query status: ${query_status:-N/A}
- require real tx cli: $REQUIRE_REAL_TX_CLI

## Next Action
- If status is NOT_READY: provide a tx-capable CLI implementation that supports and verifies lifecycle:
  - \`tx commit-result <task_id> <worker> <commit_hash> <nonce>\`
  - \`tx query <tx_hash>\`
  - Query result MUST include matching tx hash + non-empty status.
- Then run:
  - \`TRNM_TX_CLI=<your-cli> ./scripts/v2/run_worker_receipt_gates_real_cli.sh\`
EOF

echo "$REPORT"

if [[ "$REQUIRE_REAL_TX_CLI" == "1" && "$status" != "READY" ]]; then
  echo "[FAIL] real tx cli required but not ready: $reason" >&2
  exit 18
fi
