#!/usr/bin/env bash
set -euo pipefail

: "${TRNM_CHAIN_NODE_URL:?set TRNM_CHAIN_NODE_URL to the canonical live node URL}"
: "${TRNM_CHAIN_SIGNER_KEY:?set TRNM_CHAIN_SIGNER_KEY to an owner-only signer key}"
: "${TRNM_CHAIN_ID:?set TRNM_CHAIN_ID}"
: "${TRNM_CHAIN_SIGNER_ID:?set TRNM_CHAIN_SIGNER_ID}"
: "${TRNM_CHAIN_SIGNER_ROLE:?set TRNM_CHAIN_SIGNER_ROLE}"

transactions="${TRNM_BENCH_TRANSACTIONS:-100}"
payload_bytes="${TRNM_BENCH_PAYLOAD_BYTES:-256}"

exec cargo run --locked --release -p trnm-node --bin trnm-chain-cli -- \
  benchmark \
  --node-url "$TRNM_CHAIN_NODE_URL" \
  --private-key "$TRNM_CHAIN_SIGNER_KEY" \
  --chain-id "$TRNM_CHAIN_ID" \
  --signer-id "$TRNM_CHAIN_SIGNER_ID" \
  --signer-role "$TRNM_CHAIN_SIGNER_ROLE" \
  --transactions "$transactions" \
  --payload-bytes "$payload_bytes"
