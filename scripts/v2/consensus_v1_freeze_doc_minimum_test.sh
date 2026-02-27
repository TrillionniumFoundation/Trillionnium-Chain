#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOC="$ROOT/docs/protocol/consensus-v1-freeze.md"

if [[ ! -f "$DOC" ]]; then
  echo "[FAIL] missing consensus freeze doc: $DOC" >&2
  exit 1
fi

required_lines=(
  "Status: frozen-minimum (laneA)"
  "## 2) Recovery Source of Truth"
  "consensus-wal-meta.toml"
  "consensus-checkpoints.toml"
  "consensus-wal.toml"
  "## 3) Message Auth & Replay Guard"
  "run_consensus_fault_matrix.sh"
  "run_consensus_security_matrix.sh"
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq "$line" "$DOC"; then
    echo "[FAIL] consensus freeze doc missing required line: $line" >&2
    exit 1
  fi
done

if grep -Fq "status: draft" "$DOC"; then
  echo "[FAIL] consensus freeze doc still in draft scaffold state" >&2
  exit 1
fi

echo "[PASS] consensus v1 freeze doc minimum completeness checks passed"
