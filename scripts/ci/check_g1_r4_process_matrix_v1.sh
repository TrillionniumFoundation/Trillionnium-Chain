#!/usr/bin/env bash
set -euo pipefail

# Candidate-only A06 gate.  It deliberately does not invoke Cargo: the
# process/fault harness is stdlib-only so an authorized runner can execute it
# even when the Rust toolchain/cache is unavailable.  Cargo-format/test/clippy
# remain required follow-up gates once A02--A05 publish their accepted hooks.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

MATRIX="scripts/faults/g1_r4_fault_matrix_v1.py"
REPLAY="scripts/faults/g1_r4_independent_replay_v1.py"
EVIDENCE_DOC="docs/evidence/g1-r4/README.md"
EVIDENCE_CONTRACT="docs/evidence/g1-r4/fault-matrix-contract-v1.json"
PACKAGE_DOC="docs/development/packages/TRNM_G1_R4_FAULT_MATRIX_V1.md"
PACKAGE_MANIFEST="docs/development/packages/trnm-g1-r4-fault-matrix-v1.toml"
BASE_COMMIT="6e0189e351015ef3230f217ca7ff86149baedcf0"
BASE_TREE="efea864cb2fbc4835a59a089b3dbab8934e71231"

for path in "$MATRIX" "$REPLAY" "$EVIDENCE_DOC" "$EVIDENCE_CONTRACT" \
  "$PACKAGE_DOC" "$PACKAGE_MANIFEST"; do
  test -f "$path" || {
    echo "missing A06 process-matrix surface: $path" >&2
    exit 1
  }
done

test "$(git rev-parse "$BASE_COMMIT^{tree}")" = "$BASE_TREE" || {
  echo "A06 gate baseline object changed unexpectedly" >&2
  exit 1
}

python3 -m py_compile "$MATRIX" "$REPLAY"

evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/trnm-g1-r4-matrix.XXXXXX")"
chmod 700 "$evidence_dir"
evidence_json="$evidence_dir/evidence.json"

python3 "$MATRIX" --output "$evidence_json"
python3 "$REPLAY" "$evidence_json" >"$evidence_dir/replay.json"

python3 - "$evidence_json" "$evidence_dir/replay.json" <<'PY'
import json
import pathlib
import sys

evidence = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
replay = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
assert evidence["schema"] == "trnm-g1-r4-fault-matrix-v1"
assert evidence["package_id"] == "G1_R4_FAULT_MATRIX_V1"
assert evidence["status"] == "BLOCKED_UPSTREAM"
assert evidence["scope"] == "process"
assert evidence["authority"] == "candidate"
assert evidence["classification"] == "candidate-non-normative"
assert evidence["base"]["commit"] == "6e0189e351015ef3230f217ca7ff86149baedcf0"
assert evidence["base"]["tree"] == "efea864cb2fbc4835a59a089b3dbab8934e71231"
assert evidence["production_candidate"] is False
assert evidence["production_consensus_activation"] is False
assert evidence["g1_r4_exit"] is False
assert evidence["positive_count"] == 4
assert evidence["negative_count"] == 9
assert len(evidence["retained_mutants"]) == 9
assert replay["status"] == "PASS_CANDIDATE_ONLY"
assert replay["bytes_roots_and_statuses_agree"] is True
assert replay["independent_implementation"] is True
assert replay["production_authority"] is False
assert replay["g1_r4_exit"] is False
print(
    "g1_r4_process_matrix_contract=passed "
    f"cases={len(evidence['cases'])} positives={evidence['positive_count']} "
    f"negatives={evidence['negative_count']} retained_mutants={len(evidence['retained_mutants'])} "
    "sigkill=response-loss-disk-full-io-torn-rollback-skew-multiblock-fork "
    "cargo_executed=false production_candidate=false g1_r4_exit=false"
)
PY

python3 - "$EVIDENCE_CONTRACT" "$PACKAGE_MANIFEST" "$PACKAGE_DOC" <<'PY'
import json
import pathlib
import sys
import tomllib

contract = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest = tomllib.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
doc = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
assert contract["schema"] == "trnm-g1-r4-fault-matrix-contract-v1"
assert contract["status"] == "BLOCKED_UPSTREAM"
assert contract["scope"] == "process"
assert contract["authority"] == "candidate"
assert contract["candidate_only"] is True
assert contract["production_candidate"] is False
assert contract["production_consensus_activation"] is False
assert set(contract["required_faults"]) >= {
    "SIGKILL",
    "response_loss",
    "disk_full",
    "io_failure",
    "torn_write",
    "rollback",
    "skew",
    "multi_block",
    "fork",
}
assert manifest["package_id"] == "G1_R4_FAULT_MATRIX_V1"
assert manifest["status"] == "blocked-upstream"
assert manifest["base_commit"] == "6e0189e351015ef3230f217ca7ff86149baedcf0"
assert manifest["base_tree"] == "efea864cb2fbc4835a59a089b3dbab8934e71231"
assert manifest["production_candidate"] is False
assert manifest["production_consensus_activation"] is False
assert manifest["g1_r4_exit"] is False
for required in (
    "BLOCKED_UPSTREAM",
    "candidate-non-normative",
    "A02",
    "A03",
    "A04",
    "A05",
    "retained",
    "independent replay",
):
    assert required in doc, required
print("g1_r4_process_matrix_docs=passed")
PY

# This package is forbidden from changing production semantics or truth flags.
changed="$(git diff --name-only "$BASE_COMMIT"...HEAD)"
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  case "$path" in
    trillionnium/crates/trnm-poco-node/tests/*|\
      trillionnium/crates/trnm-poco-lab-validator/*|\
      scripts/ci/*process_matrix*|scripts/faults/*|\
      docs/evidence/g1-r4/*|docs/development/packages/TRNM_G1_R4_FAULT_MATRIX_V1.md|\
      docs/development/packages/trnm-g1-r4-fault-matrix-v1.toml)
      ;;
    *)
      echo "A06 gate found an out-of-scope changed path: $path" >&2
      exit 1
      ;;
  esac
done <<<"$changed"

if git diff --name-only "$BASE_COMMIT"...HEAD | grep -E '(^|/)(consensus-mainline\.json|RELEASE_READINESS\.md)$' >/dev/null; then
  echo "A06 gate forbids production/release truth changes" >&2
  exit 1
fi

echo "g1_r4_process_matrix_gate=passed status=BLOCKED_UPSTREAM source_scope=process authority=candidate cargo_executed=false"
