#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  printf 'usage: %s RPC_URL EXECUTION_HEIGHT TARGET_COMMAND_ID APPLIED_COMMAND_LOGICAL_KEY OUTPUT_DIR [research_v1|paper_raid_finality_v4]\n' "$0" >&2
  exit 2
}

[[ $# -eq 5 || $# -eq 6 ]] || usage
RPC_URL="${1%/}"
EXECUTION_HEIGHT="$2"
TARGET_COMMAND_ID="$3"
APPLIED_COMMAND_LOGICAL_KEY="$4"
OUTPUT_DIR="$5"
DOMAIN_COMMAND_VERSION="${6:-research_v1}"

case "$DOMAIN_COMMAND_VERSION" in
  research_v1)
    EXPECTED_EVENT_TYPE="trnm.research.applied.v1"
    EXPECTED_PROOF_LOG="trnm.research.applied-command.v1"
    ;;
  paper_raid_finality_v4)
    EXPECTED_EVENT_TYPE="trnm.paper-raid.finality.applied.v4"
    EXPECTED_PROOF_LOG="trnm.paper-raid.finality-applied-command.v4"
    ;;
  *) usage ;;
esac

[[ "$RPC_URL" =~ ^https?://[^/@]+(:[0-9]+)?$ ]] || {
  printf 'RPC_URL must be an http(s) origin without credentials or a path\n' >&2
  exit 2
}
[[ "$EXECUTION_HEIGHT" =~ ^[1-9][0-9]*$ ]] || {
  printf 'EXECUTION_HEIGHT must be a positive canonical decimal integer\n' >&2
  exit 2
}
[[ "$TARGET_COMMAND_ID" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'TARGET_COMMAND_ID must be 32-byte lowercase hex\n' >&2
  exit 2
}
[[ "$APPLIED_COMMAND_LOGICAL_KEY" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'APPLIED_COMMAND_LOGICAL_KEY must be 32-byte lowercase hex\n' >&2
  exit 2
}
[[ "$OUTPUT_DIR" == /* && "$OUTPUT_DIR" != / ]] || {
  printf 'OUTPUT_DIR must be an absolute non-root path\n' >&2
  exit 2
}

for command_name in base64 cmp curl jq python3 sha256sum; do
  command -v "$command_name" >/dev/null
done

if [[ -e "$OUTPUT_DIR" ]]; then
  [[ -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || {
    printf 'OUTPUT_DIR must be a real directory, not a file or symlink\n' >&2
    exit 2
  }
  [[ -z "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    printf 'OUTPUT_DIR must be empty\n' >&2
    exit 2
  }
else
  mkdir -m 700 -- "$OUTPUT_DIR"
fi

COMMITMENT_HEIGHT=$((EXECUTION_HEIGHT + 1))
[[ "$COMMITMENT_HEIGHT" -gt "$EXECUTION_HEIGHT" ]] || {
  printf 'execution height overflow\n' >&2
  exit 2
}

fetch_rpc() {
  local destination="$1"
  local endpoint="$2"
  local temporary="$destination.tmp"
  curl --fail --silent --show-error --max-time 30 "$RPC_URL$endpoint" >"$temporary"
  jq -e 'type == "object" and (.error | not) and (.result | type == "object")' \
    "$temporary" >/dev/null
  jq --sort-keys . "$temporary" >"$destination"
  rm -- "$temporary"
}

fetch_rpc "$OUTPUT_DIR/block-h.json" "/block?height=$EXECUTION_HEIGHT"
fetch_rpc "$OUTPUT_DIR/block-h-plus-1.json" "/block?height=$COMMITMENT_HEIGHT"
fetch_rpc "$OUTPUT_DIR/commit-h-plus-1.json" "/commit?height=$COMMITMENT_HEIGHT"
fetch_rpc "$OUTPUT_DIR/validators-h-plus-1.json" \
  "/validators?height=$COMMITMENT_HEIGHT&page=1&per_page=100"
fetch_rpc "$OUTPUT_DIR/block-results-h.json" "/block_results?height=$EXECUTION_HEIGHT"

query_request="$(jq -nc \
  --arg path "/object/$APPLIED_COMMAND_LOGICAL_KEY" \
  --arg height "$EXECUTION_HEIGHT" \
  '{jsonrpc:"2.0",id:"trnm-receipt-v2",method:"abci_query",params:{path:$path,data:"",height:$height,prove:true}}')"
query_tmp="$OUTPUT_DIR/applied-command-proof.json.tmp"
curl --fail --silent --show-error --max-time 30 \
  -H 'Content-Type: application/json' \
  --data-binary "$query_request" \
  "$RPC_URL" >"$query_tmp"
jq -e 'type == "object" and (.error | not) and (.result.response | type == "object")' \
  "$query_tmp" >/dev/null
jq --sort-keys . "$query_tmp" >"$OUTPUT_DIR/applied-command-proof.json"
rm -- "$query_tmp"

jq -e --arg height "$EXECUTION_HEIGHT" '
  .result.block.header.height == $height
  and (.result.block_id.hash | type == "string" and length == 64)
  and (.result.block.header.data_hash | type == "string" and length == 64)
  and ((.result.block.data.txs // []) | type == "array" and length > 0)
' "$OUTPUT_DIR/block-h.json" >/dev/null
jq -e --arg height "$COMMITMENT_HEIGHT" '
  .result.block.header.height == $height
  and (.result.block_id.hash | type == "string" and length == 64)
  and (.result.block.header.app_hash | type == "string" and length == 64)
  and (.result.block.header.last_results_hash | type == "string" and length == 64)
' "$OUTPUT_DIR/block-h-plus-1.json" >/dev/null
jq -e --arg height "$COMMITMENT_HEIGHT" '
  .result.signed_header.header.height == $height
  and (.result.signed_header.commit.height == $height)
  and (.result.signed_header.commit.block_id.hash | type == "string" and length == 64)
' "$OUTPUT_DIR/commit-h-plus-1.json" >/dev/null
jq -e --arg height "$COMMITMENT_HEIGHT" '
  .result.block_height == $height
  and ((.result.total | tonumber) > 0)
  and ((.result.total | tonumber) <= 100)
  and ((.result.validators | length) == (.result.total | tonumber))
' "$OUTPUT_DIR/validators-h-plus-1.json" >/dev/null

block_h_hash="$(jq -r '.result.block_id.hash' "$OUTPUT_DIR/block-h.json")"
block_h_plus_1_hash="$(jq -r '.result.block_id.hash' "$OUTPUT_DIR/block-h-plus-1.json")"
jq -e --arg expected "$block_h_hash" \
  '.result.block.header.last_block_id.hash == $expected' \
  "$OUTPUT_DIR/block-h-plus-1.json" >/dev/null
jq -e --slurpfile block "$OUTPUT_DIR/block-h-plus-1.json" '
  .result.signed_header.header == $block[0].result.block.header
' "$OUTPUT_DIR/commit-h-plus-1.json" >/dev/null
jq -e --arg expected "$block_h_plus_1_hash" \
  '.result.signed_header.commit.block_id.hash == $expected' \
  "$OUTPUT_DIR/commit-h-plus-1.json" >/dev/null

tx_count="$(jq -r '(.result.block.data.txs // []) | length' "$OUTPUT_DIR/block-h.json")"
jq -e --arg height "$EXECUTION_HEIGHT" '.result.height == $height' \
  "$OUTPUT_DIR/block-results-h.json" >/dev/null
result_count="$(jq -r '(.result.txs_results // .result.tx_results // []) | length' \
  "$OUTPUT_DIR/block-results-h.json")"
[[ "$tx_count" -eq "$result_count" ]] || {
  printf 'transaction/result count mismatch: %s != %s\n' "$tx_count" "$result_count" >&2
  exit 1
}

target_indices=()
for ((index = 0; index < tx_count; index++)); do
  tx_file="$OUTPUT_DIR/tx-$index.bin"
  jq -er --argjson index "$index" '.result.block.data.txs[$index]' \
    "$OUTPUT_DIR/block-h.json" | base64 --decode >"$tx_file"
  if jq -e --arg command_id "$TARGET_COMMAND_ID" \
    'type == "object" and .command_id == $command_id' "$tx_file" >/dev/null 2>&1; then
    target_indices+=("$index")
  fi
done
[[ "${#target_indices[@]}" -eq 1 ]] || {
  printf 'target command must occur exactly once; found %s\n' "${#target_indices[@]}" >&2
  exit 1
}
TARGET_INDEX="${target_indices[0]}"
cp -- "$OUTPUT_DIR/tx-$TARGET_INDEX.bin" "$OUTPUT_DIR/target-raw-tx.bin"

jq -e \
  --argjson index "$TARGET_INDEX" \
  --arg domain "$DOMAIN_COMMAND_VERSION" \
  --arg event_type "$EXPECTED_EVENT_TYPE" \
  --arg command_id "$TARGET_COMMAND_ID" \
  --arg applied_key "$APPLIED_COMMAND_LOGICAL_KEY" '
  (.result.txs_results // .result.tx_results)[$index] as $result
  | ($result.events[0].attributes // []) as $attributes
  | ($attributes | map({key:.key, value:.value}) | from_entries) as $values
  | ($attributes | map(.key)) as $keys
  | ($result | type == "object")
    and (($result.code | tonumber) == 0)
    and (($result.events // []) | length == 1)
    and ($result.events[0].type == $event_type)
    and ($values.command_id == $command_id)
    and ($values.applied_command_object_key_hex == $applied_key)
    and (if $domain == "research_v1" then
      $keys == [
        "applied_command_object_key_hex",
        "command_fingerprint_hex",
        "command_id",
        "primary_object_key_hex"
      ]
    else
      ($keys == [
        "applied_command_object_key_hex",
        "command_fingerprint_hex",
        "command_id",
        "commitment_id",
        "commitment_object_key_hex",
        "economic_eligible",
        "payload_hash_hex",
        "ranking_eligible",
        "reward_eligible",
        "scientific_finality",
        "score_eligible"
      ] or $keys == [
        "applied_command_object_key_hex",
        "command_fingerprint_hex",
        "command_id",
        "commitment_id",
        "commitment_object_key_hex",
        "economic_eligible",
        "payload_hash_hex",
        "ranking_eligible",
        "rejected_paper_bundle_hash_hex",
        "rejected_release_candidate_hash_hex",
        "rejected_rework_content_commitment_sha256_hex",
        "rejected_revision_id",
        "rejected_submission_id",
        "replacement_paper_bundle_hash_hex",
        "replacement_release_candidate_hash_hex",
        "replacement_rework_content_commitment_sha256_hex",
        "replacement_revision_id",
        "replacement_submission_id",
        "reward_eligible",
        "rework_cycle",
        "rework_id",
        "rework_index_object_key_hex",
        "scientific_finality",
        "score_eligible"
      ])
      and $values.scientific_finality == "true"
      and $values.score_eligible == "false"
      and $values.ranking_eligible == "false"
      and $values.reward_eligible == "false"
      and $values.economic_eligible == "false"
    end)
    and ([
      $result.events[0].attributes[]
      | (.index == true or .index == "true")
    ] | all)
' "$OUTPUT_DIR/block-results-h.json" >/dev/null
jq --argjson index "$TARGET_INDEX" \
  '(.result.txs_results // .result.tx_results)[$index]' \
  "$OUTPUT_DIR/block-results-h.json" >"$OUTPUT_DIR/target-result.rpc.json"

proof_json="$OUTPUT_DIR/applied-command-proof.json"
jq -e --arg height "$EXECUTION_HEIGHT" --arg proof_log "$EXPECTED_PROOF_LOG" '
  .result.response as $response
  | (($response.code | tonumber) == 0)
    and ($response.height == $height)
    and ($response.log == $proof_log)
    and ($response.key | type == "string" and length > 0)
    and ($response.value | type == "string" and length > 0)
    and (($response.proofOps.ops // $response.proof_ops.ops // []) | length == 1)
    and (($response.proofOps.ops // $response.proof_ops.ops)[0].type == "ics23:jmt:v1")
    and (($response.proofOps.ops // $response.proof_ops.ops)[0].key == $response.key)
    and (($response.proofOps.ops // $response.proof_ops.ops)[0].data | type == "string" and length > 0)
' "$proof_json" >/dev/null

jq -er '.result.response.key' "$proof_json" | base64 --decode >"$OUTPUT_DIR/proof-key.bin"
jq -er '.result.response.value' "$proof_json" | base64 --decode >"$OUTPUT_DIR/proof-value.bin"
jq -er '(.result.response.proofOps.ops // .result.response.proof_ops.ops)[0].data' \
  "$proof_json" | base64 --decode >"$OUTPUT_DIR/ics23-proof.bin"
[[ -s "$OUTPUT_DIR/proof-key.bin" && -s "$OUTPUT_DIR/proof-value.bin" \
  && -s "$OUTPUT_DIR/ics23-proof.bin" ]] || {
  printf 'ABCI proof key/value/data must decode to non-empty bytes\n' >&2
  exit 1
}

python3 - "$APPLIED_COMMAND_LOGICAL_KEY" "$OUTPUT_DIR/expected-proof-key.bin" <<'PY'
from pathlib import Path
import struct
import sys

logical = sys.argv[1].encode("ascii")
wire = (
    b"trnm/authenticated-state/v4"
    + b"\x00\x01"
    + struct.pack(">H", 1)
    + struct.pack(">I", len(logical))
    + logical
)
Path(sys.argv[2]).write_bytes(wire)
PY
cmp "$OUTPUT_DIR/expected-proof-key.bin" "$OUTPUT_DIR/proof-key.bin"

jq -n \
  --arg rpc_url "$RPC_URL" \
  --argjson execution_height "$EXECUTION_HEIGHT" \
  --argjson commitment_height "$COMMITMENT_HEIGHT" \
  --arg command_id "$TARGET_COMMAND_ID" \
  --arg applied_command_logical_key "$APPLIED_COMMAND_LOGICAL_KEY" \
  --arg domain_command_version "$DOMAIN_COMMAND_VERSION" \
  --argjson transaction_index "$TARGET_INDEX" \
  --argjson transaction_count "$tx_count" \
  '{
    schema:"trnm_research_receipt_v2_rpc_evidence_manifest_v1",
    rpc_url:$rpc_url,
    execution_height:$execution_height,
    commitment_height:$commitment_height,
    command_id:$command_id,
    domain_command_version:$domain_command_version,
    applied_command_logical_key:$applied_command_logical_key,
    transaction_index:$transaction_index,
    transaction_count:$transaction_count,
    canonicalization_boundary:{
      rpc_json:"semantically normalized with jq --sort-keys",
      raw_transaction:"exact decoded block transaction bytes",
      abci_proof:"exact decoded key/value/ICS23 bytes",
      protobuf:"must be reconstructed and canonical-encoded by the Rust Receipt V2 assembler; this collector never fabricates protobuf bytes"
    }
  }' >"$OUTPUT_DIR/manifest.json"

(
  cd "$OUTPUT_DIR"
  sha256sum \
    applied-command-proof.json \
    block-h-plus-1.json \
    block-h.json \
    block-results-h.json \
    commit-h-plus-1.json \
    expected-proof-key.bin \
    ics23-proof.bin \
    manifest.json \
    proof-key.bin \
    proof-value.bin \
    target-raw-tx.bin \
    target-result.rpc.json \
    validators-h-plus-1.json >SHA256SUMS
)

printf 'TRNM_RESEARCH_RECEIPT_V2_EVIDENCE_COLLECTED dir=%s height=%s index=%s\n' \
  "$OUTPUT_DIR" "$EXECUTION_HEIGHT" "$TARGET_INDEX"
