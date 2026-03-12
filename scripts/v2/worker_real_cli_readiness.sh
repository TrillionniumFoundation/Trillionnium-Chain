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

resolve_tx_cli() {
  local candidate="$1"
  if command -v "$candidate" >/dev/null 2>&1; then
    command -v "$candidate"
    return 0
  fi

  if [[ "$candidate" == "trnm-cli" ]]; then
    local cargo_bin="$ROOT/trillionnium-rust/target/debug/trnm-cli"
    if [[ -x "$cargo_bin" ]]; then
      printf "%s\n" "$cargo_bin"
      return 0
    fi
  fi

  return 1
}

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
  local h=""
  while IFS= read -r tok; do
    tok="$(printf "%s" "$tok" | sed -E "s/.*[:=][[:space:]]*//")"
    tok="$(printf "%s" "$tok" | sed -E 's/^[[:space:]"'"'"'`({\[]+//; s/[[:space:]"'"'"'`,;:)}\]]+$//')"
    tok="${tok#0x}"
    tok="${tok#0X}"
    if [[ "$tok" =~ ^[0-9A-Fa-f]{16,128}$ ]]; then
      h="$tok"
      break
    fi
  done < <(printf "%s\n" "$raw" | grep -Eio '(tx_hash|txhash|txHash|transaction_hash|transactionHash)"?[[:space:]]*[:=][[:space:]]*["'"'"'`(\[{]*(0[xX])?[0-9A-Fa-f]{16,128}["'"'"'`,;:)}\]]*')
  printf "%s" "$h"
}

extract_query_status() {
  local raw="$1"
  local s
  # Accept plain-text lifecycle aliases like: status=ok / tx_status: committed /
  # state=finalized, including log-prefixed lines (e.g. "[info] state=committed").
  s=$(printf "%s\n" "$raw" \
    | grep -Eio '(^|[^A-Za-z0-9_])(([Tt][Xx]|[Tt][Rr][Aa][Nn][Ss][Aa][Cc][Tt][Ii][Oo][Nn])_)?([Ss][Tt][Aa][Tt][Uu][Ss]|[Ss][Tt][Aa][Tt][Ee])[[:space:]]*[:=][[:space:]]*[^[:space:]]+' \
    | head -n1 \
    | sed -E 's/.*[[:space:]:=]([^[:space:]]+).*/\1/' || true)
  if [[ -z "$s" ]]; then
    # Accept JSON variants with either status/state aliases to avoid false negatives across adapters.
    s=$(printf "%s\n" "$raw" | grep -Eio '"((tx_|transaction_)?status|(tx_|transaction_)?state)"[[:space:]]*:[[:space:]]*"[^"]+"|"transactionStatus"[[:space:]]*:[[:space:]]*"[^"]+"|"txStatus"[[:space:]]*:[[:space:]]*"[^"]+"|"transactionState"[[:space:]]*:[[:space:]]*"[^"]+"|"txState"[[:space:]]*:[[:space:]]*"[^"]+"' | sed -E 's/.*:[[:space:]]*"([^"]+)"/\1/' | head -n1 || true)
  fi
  if [[ -z "$s" ]]; then
    # Also accept non-string JSON scalar lifecycle values (number/bool), preserving guardrail against empty/null.
    s=$(printf "%s\n" "$raw" | grep -Eio '"((tx_|transaction_)?status|(tx_|transaction_)?state)"[[:space:]]*:[[:space:]]*(true|false|[0-9]+)|"transactionStatus"[[:space:]]*:[[:space:]]*(true|false|[0-9]+)|"txStatus"[[:space:]]*:[[:space:]]*(true|false|[0-9]+)|"transactionState"[[:space:]]*:[[:space:]]*(true|false|[0-9]+)|"txState"[[:space:]]*:[[:space:]]*(true|false|[0-9]+)' | sed -E 's/.*:[[:space:]]*(true|false|[0-9]+).*/\1/' | head -n1 || true)
  fi
  printf "%s" "$s"
}

if TX_CLI_RESOLVED="$(resolve_tx_cli "$TX_CLI")"; then
  TX_CLI="$TX_CLI_RESOLVED"
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

        query_retries="${TRNM_REALCLI_QUERY_RETRIES:-3}"
        query_retry_sleep="${TRNM_REALCLI_QUERY_RETRY_SLEEP_SEC:-1}"
        commit_tx_hash_lc="$(printf "%s" "$commit_tx_hash" | tr '[:upper:]' '[:lower:]')"

        for ((attempt=1; attempt<=query_retries; attempt++)); do
          set +e
          query_out=$("$TX_CLI" tx query "$commit_tx_hash" 2>&1)
          query_rc=$?
          set -e

          if [[ $query_rc -eq 0 ]]; then
            query_ok="yes"
            query_seen_hash="$(extract_tx_hash "$query_out")"
            query_status="$(extract_query_status "$query_out")"
            query_seen_hash_lc="$(printf "%s" "$query_seen_hash" | tr '[:upper:]' '[:lower:]')"
            query_status_lc="$(printf "%s" "$query_status" | tr '[:upper:]' '[:lower:]')"

            if [[ -n "$query_seen_hash" && "$query_seen_hash_lc" == "$commit_tx_hash_lc" ]]; then
              query_hash_match="yes"
            fi
            # Guardrail: reject placeholder/negative status values to avoid false READY.
            if [[ "$query_hash_match" == "yes" && -n "$query_status" \
                  && "$query_status_lc" != "null" && "$query_status_lc" != "none" \
                  && "$query_status_lc" != "unknown" && "$query_status_lc" != "false" \
                  && "$query_status_lc" != "0" ]]; then
              status="READY"
              reason="tx lifecycle verified (commit + query visible)"
              break
            fi
            reason="tx query output missing required fields (hash/status consistency + non-placeholder status)"
          else
            reason="tx query failed for submitted tx_hash=$commit_tx_hash"
          fi

          if (( attempt < query_retries )); then
            sleep "$query_retry_sleep"
          fi
        done
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
  if [[ "$TX_CLI" == "trnm-cli" ]]; then
    reason="tx cli not found via PATH or fallback build artifact: $TX_CLI"
  else
    reason="tx cli not found in PATH: $TX_CLI"
  fi
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
