#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODE="${TRNM_SOAK_MODE:-smoke}"
ITERATIONS="${TRNM_SOAK_ITERATIONS:-1}"
EVIDENCE_ROOT="${TRNM_SOAK_EVIDENCE_ROOT:-$PWD/run/cometbft-local-repetition/$(date -u +%Y%m%dT%H%M%SZ)}"
COMETBFT_BIN="${TRNM_COMETBFT_BIN:-cometbft}"

case "$MODE" in
  smoke | test)
    ;;
  72h | 7d | multihost)
    printf '%s\n' \
      "TRNM_SOAK_MODE=$MODE is intentionally unavailable: this repository has no continuous multi-host soak orchestrator." \
      "Use smoke/test only for local loopback repetition; do not cite it as long-duration or public-testnet evidence." >&2
    exit 2
    ;;
  *)
    printf 'unsupported TRNM_SOAK_MODE=%s (allowed: smoke, test)\n' "$MODE" >&2
    exit 2
    ;;
esac

if [[ ! "$ITERATIONS" =~ ^[1-9][0-9]*$ ]]; then
  printf 'TRNM_SOAK_ITERATIONS must be a positive integer, got %s\n' "$ITERATIONS" >&2
  exit 2
fi

command -v "$COMETBFT_BIN" >/dev/null
command -v jq >/dev/null
command -v sha256sum >/dev/null
mkdir -p "$EVIDENCE_ROOT/runs"

write_summary() {
  local result="$1"
  local completed="$2"
  local failed_iteration="${3:-}"

  jq -n \
    --arg schema trnm_cometbft_local_repetition_summary_v1 \
    --arg scope local-loopback-repetition-smoke \
    --arg mode "$MODE" \
    --arg result "$result" \
    --arg failed_iteration "$failed_iteration" \
    --argjson requested_iterations "$ITERATIONS" \
    --argjson completed_iterations "$completed" \
    '{
      schema: $schema,
      scope: $scope,
      mode: $mode,
      requested_iterations: $requested_iterations,
      completed_iterations: $completed_iterations,
      result: $result,
      long_duration_soak: false,
      multi_host: false,
      public_testnet_evidence: false
    }
    + if $failed_iteration == "" then {} else {failed_iteration: ($failed_iteration | tonumber)} end' \
    >"$EVIDENCE_ROOT/summary.json"
}

completed=0
for ((iteration = 1; iteration <= ITERATIONS; iteration++)); do
  run_root="$EVIDENCE_ROOT/runs/$iteration"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  set +e
  output="$(TRNM_COMETBFT_BIN="$COMETBFT_BIN" TRNM_COMETBFT_SPIKE_ROOT="$run_root" TRNM_COMETBFT_SPIKE_KEEP=1 "$SCRIPT_DIR/spike_cometbft_four_validator.sh" 2>&1)"
  status=$?
  set -e

  printf '%s\n' "$output" >"$EVIDENCE_ROOT/runs/$iteration.log"
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  marker="$(printf '%s\n' "$output" | awk '/^TRNM_COMETBFT_FOUR_VALIDATOR_OK / { marker=$0 } END { print marker }')"
  canonical_evidence="$run_root/evidence/canonical-vertical-slice.json"
  safety_evidence="$run_root/evidence/safety-evidence.json"
  evidence_valid=false
  canonical_sha256=""
  safety_sha256=""

  if [[ "$status" -eq 0 ]] \
    && [[ -n "$marker" ]] \
    && jq -e . "$canonical_evidence" >/dev/null \
    && jq -e . "$safety_evidence" >/dev/null; then
    evidence_valid=true
    canonical_sha256="$(sha256sum "$canonical_evidence" | awk '{print $1}')"
    safety_sha256="$(sha256sum "$safety_evidence" | awk '{print $1}')"
  elif [[ "$status" -eq 0 ]]; then
    status=3
  fi

  jq -n \
    --argjson iteration "$iteration" \
    --arg started "$started" \
    --arg finished "$finished" \
    --argjson status "$status" \
    --arg marker "$marker" \
    --argjson evidence_valid "$evidence_valid" \
    --arg canonical_evidence "$canonical_evidence" \
    --arg canonical_sha256 "$canonical_sha256" \
    --arg safety_evidence "$safety_evidence" \
    --arg safety_sha256 "$safety_sha256" \
    '{
      iteration: $iteration,
      started_at: $started,
      finished_at: $finished,
      status: $status,
      marker: $marker,
      evidence_valid: $evidence_valid,
      canonical_evidence: $canonical_evidence,
      canonical_sha256: $canonical_sha256,
      safety_evidence: $safety_evidence,
      safety_sha256: $safety_sha256
    }' >"$EVIDENCE_ROOT/runs/$iteration.json"

  if [[ "$status" -ne 0 ]]; then
    write_summary fail "$completed" "$iteration"
    printf 'TRNM_LOCAL_REPETITION_FAILED iteration=%s evidence=%s\n' "$iteration" "$EVIDENCE_ROOT" >&2
    exit "$status"
  fi

  completed="$iteration"
done

write_summary pass "$completed"
printf 'TRNM_LOCAL_REPETITION_OK mode=%s iterations=%s evidence=%s scope=local-loopback-only\n' \
  "$MODE" "$completed" "$EVIDENCE_ROOT"
