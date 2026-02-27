#!/usr/bin/env bash
set -euo pipefail

# Minimal tx-capable CLI wrapper for worker gate integration.
# Interface:
#   trnm_tx_cli_wrapper.sh tx --help
#   trnm_tx_cli_wrapper.sh tx commit-result <task_id> <worker> <commit_hash> <nonce>
#   trnm_tx_cli_wrapper.sh tx reveal-result <task_id> <result_hash> <salt_hex>
#   trnm_tx_cli_wrapper.sh tx query <tx_hash>

if [[ "${1:-}" != "tx" ]]; then
  echo "usage: $0 tx <commit-result|reveal-result|--help> ..." >&2
  exit 2
fi

sub="${2:-}"
if [[ "$sub" == "--help" || "$sub" == "-h" || -z "$sub" ]]; then
  cat <<'EOF'
trnm-tx-cli-wrapper

Usage:
  tx commit-result <task_id> <worker> <commit_hash> <nonce>
  tx reveal-result <task_id> <result_hash> <salt_hex>
  tx query <tx_hash>
EOF
  exit 0
fi

stable_tx_hash() {
  local payload="$1"
  printf "%s" "$payload" | shasum -a 256 | awk '{print $1}'
}

case "$sub" in
  commit-result)
    if [[ "$#" -ne 6 ]]; then
      echo "invalid args for commit-result: expected 4 payload args" >&2
      exit 2
    fi
    task_id="${3:-}"
    worker="${4:-}"
    commit_hash="${5:-}"
    nonce="${6:-}"
    [[ -n "$task_id" && -n "$worker" && -n "$commit_hash" && -n "$nonce" ]] || {
      echo "invalid args for commit-result" >&2
      exit 2
    }
    tx_hash="$(stable_tx_hash "commit|$task_id|$worker|$commit_hash|$nonce")"
    echo "tx_hash=$tx_hash"
    ;;
  reveal-result)
    if [[ "$#" -ne 5 ]]; then
      echo "invalid args for reveal-result: expected 3 payload args" >&2
      exit 2
    fi
    task_id="${3:-}"
    result_hash="${4:-}"
    salt_hex="${5:-}"
    [[ -n "$task_id" && -n "$result_hash" && -n "$salt_hex" ]] || {
      echo "invalid args for reveal-result" >&2
      exit 2
    }
    tx_hash="$(stable_tx_hash "reveal|$task_id|$result_hash|$salt_hex")"
    echo "tx_hash=$tx_hash"
    ;;
  query)
    if [[ "$#" -ne 3 ]]; then
      echo "invalid args for query: expected tx_hash only" >&2
      exit 2
    fi
    tx_hash="${3:-}"
    [[ -n "$tx_hash" ]] || {
      echo "invalid args for query" >&2
      exit 2
    }
    echo "tx_hash=$tx_hash"
    echo "status=committed"
    ;;
  *)
    echo "unknown tx subcommand: $sub" >&2
    exit 2
    ;;
esac
