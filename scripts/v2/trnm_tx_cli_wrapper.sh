#!/usr/bin/env bash
set -euo pipefail

# Minimal tx-capable CLI wrapper for worker gate integration.
# Interface:
#   trnm_tx_cli_wrapper.sh tx --help
#   trnm_tx_cli_wrapper.sh tx commit-result <task_id> <worker> <commit_hash> <nonce>
#   trnm_tx_cli_wrapper.sh tx reveal-result <task_id> <result_hash> <salt_hex>

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
EOF
  exit 0
fi

case "$sub" in
  commit-result)
    task_id="${3:-}"
    worker="${4:-}"
    commit_hash="${5:-}"
    nonce="${6:-}"
    [[ -n "$task_id" && -n "$worker" && -n "$commit_hash" && -n "$nonce" ]] || {
      echo "invalid args for commit-result" >&2
      exit 2
    }
    echo "[tx-cli-wrapper] commit-result accepted task_id=$task_id worker=$worker nonce=$nonce"
    ;;
  reveal-result)
    task_id="${3:-}"
    result_hash="${4:-}"
    salt_hex="${5:-}"
    [[ -n "$task_id" && -n "$result_hash" && -n "$salt_hex" ]] || {
      echo "invalid args for reveal-result" >&2
      exit 2
    }
    echo "[tx-cli-wrapper] reveal-result accepted task_id=$task_id"
    ;;
  *)
    echo "unknown tx subcommand: $sub" >&2
    exit 2
    ;;
esac
